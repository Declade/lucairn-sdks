// Package anchor verifies the two external anchors a Lucairn certificate
// carries, offline and with the standard library only:
//
//   - the RFC 3161 timestamp token (attestation.timestamp), against a pinned
//     TSA root certificate;
//   - the Sigstore Rekor entry (attestation.transparency_log), against the
//     pinned Rekor public key.
//
// Nothing here reads anchor_status: a certificate's own statement that it is
// anchored is never evidence that it is.
//
// Scope, stated once (it is repeated in the CLI output): both anchors commit
// to a digest of the witness's stored certificate bytes. Those bytes are not
// part of an evidence bundle (before the 30-day decoder expiry they carry the
// original values that never leave Lucairn), so this package proves that a
// trusted timestamp authority and the public transparency log committed to
// the digest the certificate RECORDS, at the time they say. It does not, by
// itself, prove that digest is the digest of this certificate's bytes.
package anchor

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // ESS signingCertificate (v1) names SHA-1 by definition; only compared, never trusted alone
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
	"time"
)

// FreeTSARootPEM is the pinned FreeTSA root certificate
// (https://freetsa.org/files/cacert.pem), the same file and checksum the
// Lucairn witness pins (dual-sandbox-architecture
// services/veil-witness/internal/verifier/trustroots/freetsa.pem).
//
//go:embed trustroots/freetsa.pem
var FreeTSARootPEM []byte

// FreeTSARootSHA256 pins the embedded PEM bytes; anchor_test.go recomputes it.
const FreeTSARootSHA256 = "2151b61137ffa86bf664691ba67e7da0b19f98c758e3d228d5d8ebf27e044438"

// ClockSkew is the tolerance for comparing an anchor time with the
// certificate's issued_at and with certificate validity windows.
const ClockSkew = 5 * time.Minute

var (
	oidSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningCert   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidAttrSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSAWithSHA2 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3} // prefix of ecdsa-with-SHA256/384/512
	oidEd25519       = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// AlgorithmIdentifier is the X.509 / CMS AlgorithmIdentifier.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString []asn1.RawValue `asn1:"optional"`
	FailInfo     asn1.BitString  `asn1:"optional"`
}

type timeStampResp struct {
	Status pkiStatusInfo
	Token  asn1.RawValue `asn1:"optional"`
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms asn1.RawValue
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      asn1.RawValue
}

type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// MessageImprint is the RFC 3161 MessageImprint.
type MessageImprint struct {
	HashAlgorithm AlgorithmIdentifier
	HashedMessage []byte
}

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time     `asn1:"generalized"`
	Rest           asn1.RawValue `asn1:"optional"` // accuracy / ordering / nonce / tsa / extensions: not needed
}

type essCertID struct {
	CertHash []byte
	Rest     asn1.RawValue `asn1:"optional"`
}

type signingCertificate struct {
	Certs []essCertID
	Rest  asn1.RawValue `asn1:"optional"`
}

type essCertIDv2 struct {
	HashAlgorithm AlgorithmIdentifier `asn1:"optional"`
	CertHash      []byte
	Rest          asn1.RawValue `asn1:"optional"`
}

type signingCertificateV2 struct {
	Certs []essCertIDv2
	Rest  asn1.RawValue `asn1:"optional"`
}

// TimestampResult is what a successfully verified token states.
type TimestampResult struct {
	GenTime time.Time
	Signer  string // subject of the TSA signing certificate
	// ChainValidNow is false when the signing chain was valid at GenTime but
	// is no longer valid today (expired). Revocation is not checked offline.
	ChainValidNow bool
}

// VerifyTimestamp verifies an RFC 3161 token (a TimeStampResp, or a bare
// TimeStampToken ContentInfo) offline:
//
//  1. structure: granted status, CMS SignedData, eContentType id-ct-TSTInfo;
//  2. messageImprint: SHA-256, equal to expectedDigest;
//  3. signed attributes: content-type, message-digest = hash(TSTInfo), and an
//     ESS signing-certificate(-v2) attribute naming the signer certificate;
//  4. the CMS signature over the signed attributes, under the signer
//     certificate's key;
//  5. the signer certificate chains to roots for time-stamping at GenTime.
//
// Every failure is an error; nothing is skipped silently.
func VerifyTimestamp(token, expectedDigest []byte, roots *x509.CertPool, now time.Time) (*TimestampResult, error) {
	if len(token) == 0 {
		return nil, errors.New("timestamp token is empty")
	}
	if len(expectedDigest) != sha256.Size {
		return nil, fmt.Errorf("recorded digest must be %d bytes (SHA-256), got %d", sha256.Size, len(expectedDigest))
	}
	ciBytes, err := unwrapTimeStampResp(token)
	if err != nil {
		return nil, err
	}
	var ci contentInfo
	if rest, err := asn1.Unmarshal(ciBytes, &ci); err != nil {
		return nil, fmt.Errorf("token is not a CMS ContentInfo: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("trailing bytes after the timestamp token")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("token content type %v is not SignedData", ci.ContentType)
	}
	var sd signedData
	if rest, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("token SignedData does not parse: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("trailing bytes after SignedData")
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return nil, fmt.Errorf("encapsulated content type %v is not id-ct-TSTInfo", sd.EncapContentInfo.EContentType)
	}
	var eContent []byte
	if rest, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &eContent); err != nil {
		return nil, fmt.Errorf("TSTInfo is not a DER OCTET STRING: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("trailing bytes after the TSTInfo OCTET STRING")
	}
	var tst tstInfo
	if rest, err := asn1.Unmarshal(eContent, &tst); err != nil {
		return nil, fmt.Errorf("TSTInfo does not parse: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("trailing bytes after TSTInfo")
	}
	if !tst.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		return nil, fmt.Errorf("token message imprint uses %v, not SHA-256", tst.MessageImprint.HashAlgorithm.Algorithm)
	}
	if !bytes.Equal(tst.MessageImprint.HashedMessage, expectedDigest) {
		return nil, errors.New("token message imprint does not equal the digest the certificate records (the token timestamps other bytes)")
	}
	if tst.GenTime.IsZero() {
		return nil, errors.New("token carries no genTime")
	}

	certs, err := parseCertificateSet(sd.Certificates)
	if err != nil {
		return nil, err
	}
	var signers []signerInfo
	rest := sd.SignerInfos.Bytes
	for len(rest) > 0 {
		var si signerInfo
		rest, err = asn1.Unmarshal(rest, &si)
		if err != nil {
			return nil, fmt.Errorf("SignerInfo does not parse: %w", err)
		}
		signers = append(signers, si)
	}
	if len(signers) != 1 {
		return nil, fmt.Errorf("token must carry exactly one SignerInfo, got %d", len(signers))
	}
	si := signers[0]
	signer, err := findSigner(si.SID, certs)
	if err != nil {
		return nil, err
	}
	if len(si.SignedAttrs.FullBytes) == 0 {
		return nil, errors.New("SignerInfo has no signed attributes")
	}
	digestHash, err := hashFor(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return nil, err
	}
	if err := checkSignedAttrs(si.SignedAttrs.Bytes, digestHash, eContent, signer); err != nil {
		return nil, err
	}
	// The signature covers the DER of the attributes as a SET OF (tag 0x31),
	// not as the [0] IMPLICIT field it is stored in (RFC 5652 § 5.4).
	signedBytes := append([]byte{0x31}, si.SignedAttrs.FullBytes[1:]...)
	if err := checkCMSSignature(signer, si.SignatureAlgorithm, digestHash, signedBytes, si.Signature); err != nil {
		return nil, err
	}

	if err := checkTimestampingEKU(signer); err != nil {
		return nil, err
	}
	if tst.GenTime.After(now.Add(ClockSkew)) {
		return nil, fmt.Errorf("token genTime %s is in the future", tst.GenTime.UTC().Format(time.RFC3339))
	}
	intermediates := x509.NewCertPool()
	for _, c := range certs {
		if c != signer {
			intermediates.AddCert(c)
		}
	}
	verifyAt := func(at time.Time) error {
		_, err := signer.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			CurrentTime:   at,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		})
		return err
	}
	if err := verifyAt(tst.GenTime); err != nil {
		return nil, fmt.Errorf("TSA signing certificate does not chain to the pinned root for time-stamping at genTime: %w", err)
	}
	return &TimestampResult{
		GenTime:       tst.GenTime.UTC(),
		Signer:        signer.Subject.String(),
		ChainValidNow: verifyAt(now) == nil,
	}, nil
}

// unwrapTimeStampResp returns the ContentInfo bytes, accepting either a full
// TimeStampResp (what the witness stores: FreeTSA's HTTP response body) or a
// bare TimeStampToken.
func unwrapTimeStampResp(b []byte) ([]byte, error) {
	var probe asn1.RawValue
	if _, err := asn1.Unmarshal(b, &probe); err != nil {
		return nil, fmt.Errorf("timestamp token is not DER: %w", err)
	}
	// A ContentInfo starts with an OID; a TimeStampResp starts with the
	// PKIStatusInfo SEQUENCE.
	var first asn1.RawValue
	if _, err := asn1.Unmarshal(probe.Bytes, &first); err != nil {
		return nil, fmt.Errorf("timestamp token is not DER: %w", err)
	}
	if first.Tag == asn1.TagOID {
		return b, nil
	}
	var resp timeStampResp
	rest, err := asn1.Unmarshal(b, &resp)
	if err != nil {
		return nil, fmt.Errorf("TimeStampResp does not parse: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("trailing bytes after TimeStampResp")
	}
	if resp.Status.Status != 0 && resp.Status.Status != 1 {
		return nil, fmt.Errorf("TimeStampResp status %d is not granted", resp.Status.Status)
	}
	if len(resp.Token.FullBytes) == 0 {
		return nil, errors.New("TimeStampResp carries no token")
	}
	return resp.Token.FullBytes, nil
}

func parseCertificateSet(raw asn1.RawValue) ([]*x509.Certificate, error) {
	if len(raw.Bytes) == 0 {
		return nil, errors.New("token carries no certificates (the TSA signing certificate is required)")
	}
	var out []*x509.Certificate
	rest := raw.Bytes
	for len(rest) > 0 {
		var one asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &one)
		if err != nil {
			return nil, fmt.Errorf("token certificate set does not parse: %w", err)
		}
		if one.Class != asn1.ClassUniversal || one.Tag != asn1.TagSequence {
			continue // other CertificateChoices (attribute certs etc.) are not signers
		}
		c, err := x509.ParseCertificate(one.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("token certificate does not parse: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("token carries no X.509 certificates")
	}
	return out, nil
}

func findSigner(sid asn1.RawValue, certs []*x509.Certificate) (*x509.Certificate, error) {
	switch {
	case sid.Class == asn1.ClassUniversal && sid.Tag == asn1.TagSequence:
		var ias issuerAndSerial
		if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil {
			return nil, fmt.Errorf("SignerIdentifier does not parse: %w", err)
		}
		for _, c := range certs {
			if c.SerialNumber.Cmp(ias.Serial) == 0 && bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) {
				return c, nil
			}
		}
	case sid.Class == asn1.ClassContextSpecific && sid.Tag == 0:
		for _, c := range certs {
			if len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, sid.Bytes) {
				return c, nil
			}
		}
	default:
		return nil, errors.New("SignerIdentifier has an unknown form")
	}
	return nil, errors.New("the signer certificate is not in the token")
}

func hashFor(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("unsupported digest algorithm %v", oid)
}

func newHash(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA384:
		return sha512.New384()
	case crypto.SHA512:
		return sha512.New()
	default:
		return sha256.New()
	}
}

func sum(h crypto.Hash, b []byte) []byte {
	x := newHash(h)
	x.Write(b)
	return x.Sum(nil)
}

func checkSignedAttrs(attrsSetBody []byte, h crypto.Hash, eContent []byte, signer *x509.Certificate) error {
	var gotType, gotDigest, gotESS bool
	rest := attrsSetBody
	for len(rest) > 0 {
		var a attribute
		var err error
		rest, err = asn1.Unmarshal(rest, &a)
		if err != nil {
			return fmt.Errorf("signed attribute does not parse: %w", err)
		}
		switch {
		case a.Type.Equal(oidAttrContentType):
			var ct asn1.ObjectIdentifier
			if _, err := asn1.Unmarshal(a.Values.Bytes, &ct); err != nil || !ct.Equal(oidTSTInfo) {
				return errors.New("signed content-type attribute is not id-ct-TSTInfo")
			}
			gotType = true
		case a.Type.Equal(oidAttrMessageDigest):
			var md []byte
			if _, err := asn1.Unmarshal(a.Values.Bytes, &md); err != nil {
				return errors.New("signed message-digest attribute does not parse")
			}
			if !bytes.Equal(md, sum(h, eContent)) {
				return errors.New("signed message-digest does not match the TSTInfo (the timestamp content was altered)")
			}
			gotDigest = true
		case a.Type.Equal(oidAttrSigningCert):
			var sc signingCertificate
			if _, err := asn1.Unmarshal(a.Values.Bytes, &sc); err != nil || len(sc.Certs) == 0 {
				return errors.New("ESS signing-certificate attribute does not parse")
			}
			want := sha1.Sum(signer.Raw) //nolint:gosec // see import note
			if !bytes.Equal(sc.Certs[0].CertHash, want[:]) {
				return errors.New("ESS signing-certificate does not name the signer certificate")
			}
			gotESS = true
		case a.Type.Equal(oidAttrSigningCertV2):
			var sc signingCertificateV2
			if _, err := asn1.Unmarshal(a.Values.Bytes, &sc); err != nil || len(sc.Certs) == 0 {
				return errors.New("ESS signing-certificate-v2 attribute does not parse")
			}
			ch := crypto.SHA256 // RFC 5035 default
			if len(sc.Certs[0].HashAlgorithm.Algorithm) > 0 {
				var err error
				if ch, err = hashFor(sc.Certs[0].HashAlgorithm.Algorithm); err != nil {
					return err
				}
			}
			if !bytes.Equal(sc.Certs[0].CertHash, sum(ch, signer.Raw)) {
				return errors.New("ESS signing-certificate-v2 does not name the signer certificate")
			}
			gotESS = true
		}
	}
	if !gotType || !gotDigest {
		return errors.New("signed attributes lack content-type or message-digest")
	}
	if !gotESS {
		return errors.New("signed attributes lack the ESS signing-certificate attribute RFC 3161 requires")
	}
	return nil
}

func checkCMSSignature(signer *x509.Certificate, alg AlgorithmIdentifier, h crypto.Hash, signed, sig []byte) error {
	switch pub := signer.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !hasPrefix(alg.Algorithm, oidECDSAWithSHA2) && !alg.Algorithm.Equal(oidECPublicKey) {
			return fmt.Errorf("signature algorithm %v does not match the ECDSA signer key", alg.Algorithm)
		}
		if !ecdsa.VerifyASN1(pub, sum(h, signed), sig) {
			return errors.New("TSA signature does not verify under the signer certificate")
		}
	case *rsa.PublicKey:
		switch {
		case alg.Algorithm.Equal(oidRSAEncryption), alg.Algorithm.Equal(oidSHA256WithRSA),
			alg.Algorithm.Equal(oidSHA384WithRSA), alg.Algorithm.Equal(oidSHA512WithRSA):
		default:
			return fmt.Errorf("unsupported RSA signature algorithm %v", alg.Algorithm)
		}
		if err := rsa.VerifyPKCS1v15(pub, h, sum(h, signed), sig); err != nil {
			return errors.New("TSA signature does not verify under the signer certificate")
		}
	case ed25519.PublicKey:
		if !alg.Algorithm.Equal(oidEd25519) {
			return fmt.Errorf("signature algorithm %v does not match the Ed25519 signer key", alg.Algorithm)
		}
		if !ed25519.Verify(pub, signed, sig) {
			return errors.New("TSA signature does not verify under the signer certificate")
		}
	default:
		return fmt.Errorf("unsupported TSA key type %T", signer.PublicKey)
	}
	return nil
}

var oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}

// checkTimestampingEKU enforces RFC 3161 § 2.3: the TSA certificate carries
// exactly one extended-key-usage extension, it is CRITICAL, and its only
// purpose is id-kp-timeStamping (OpenSSL's `ts -verify` enforces the same).
func checkTimestampingEKU(c *x509.Certificate) error {
	found := 0
	for _, e := range c.Extensions {
		if e.Id.Equal(oidExtKeyUsage) {
			found++
			if !e.Critical {
				return errors.New("TSA certificate's extended key usage is not critical (RFC 3161 § 2.3)")
			}
		}
	}
	if found != 1 || len(c.ExtKeyUsage) != 1 || c.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping || len(c.UnknownExtKeyUsage) != 0 {
		return errors.New("TSA certificate must carry exactly one extended key usage: time stamping (RFC 3161 § 2.3)")
	}
	return nil
}

func hasPrefix(oid, prefix asn1.ObjectIdentifier) bool {
	if len(oid) < len(prefix) {
		return false
	}
	return oid[:len(prefix)].Equal(prefix)
}
