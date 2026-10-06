package anchor

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/verify"
)

// RekorPublicGoodPEM is the public key of the Sigstore public-good Rekor log
// (https://rekor.sigstore.dev), log ID
// c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d — as
// published in the Sigstore TUF trusted root (tlogs[0], valid from
// 2021-01-12) and as pinned in the witness's own Rekor verifier tests.
//
//go:embed trustroots/rekor-public-good.pem
var RekorPublicGoodPEM []byte

// RekorPublicGoodLogID is sha256(SPKI DER) of RekorPublicGoodPEM.
const RekorPublicGoodLogID = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"

// RekorKey is a pinned Rekor log key with its log ID (sha256 of the SPKI DER).
type RekorKey struct {
	Public *ecdsa.PublicKey
	LogID  string
}

// ParseRekorKeyPEM loads an ECDSA Rekor public key from PEM.
func ParseRekorKeyPEM(b []byte) (*RekorKey, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("Rekor key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Rekor key does not parse: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Rekor key must be ECDSA, got %T", pub)
	}
	id := sha256.Sum256(block.Bytes)
	return &RekorKey{Public: ec, LogID: hex.EncodeToString(id[:])}, nil
}

// RekorEntry is the transparency-log half of a certificate's attestation, as
// the witness stores it (proto TransparencyLogEntry).
type RekorEntry struct {
	LogIndex             int64  // global log index (the SET signs it)
	InclusionProof       []byte // Rekor's verification.inclusionProof JSON, verbatim
	SignedEntryTimestamp []byte // raw SET signature bytes
	CanonicalBody        []byte // the JCS hashedrekord body the witness POSTed
	IntegratedTime       int64  // unix seconds, signed by the SET
}

// RekorResult is what a successfully verified entry states.
type RekorResult struct {
	IntegratedTime time.Time
	// ArtifactSHA512 is the digest the entry logs (hex), signed by the witness.
	ArtifactSHA512 string
	// Checkpoint is true when the inclusion proof carried a Rekor-signed
	// checkpoint that verified and commits to the proof's root hash. Since
	// round 2 of T-1231 S1 a proof WITHOUT a signed checkpoint is an error
	// (an unsigned root proves nothing), so a nil error implies true.
	Checkpoint bool
}

// ErrRekorNoBody marks an entry anchored before the witness stored the
// canonical body: its SET cannot be checked offline.
var ErrRekorNoBody = errors.New("the entry carries no canonical body or integrated time (anchored before the witness stored them)")

// VerifyRekor verifies a stored Rekor entry offline:
//
//  1. the signed entry timestamp (SET) under the pinned Rekor key, over
//     {body, integratedTime, logID, logIndex} (RFC 8785 canonical JSON);
//  2. the inclusion proof: the RFC 6962 leaf hash of the body walks to the
//     proof's root hash, and the proof's checkpoint — REQUIRED: a root hash
//     without one is just a number the bundle supplies — is signed by the
//     pinned Rekor key and names the same root and tree size. The proof's
//     tree index may not exceed the SET-signed log index (Rekor numbers its
//     shards so that global index = shard offset + tree index);
//  3. the body: a hashedrekord v0.0.1 whose public key is the witness key and
//     whose Ed25519ph signature over the SHA-512 digest verifies under it —
//     i.e. the witness itself logged this digest.
func VerifyRekor(e RekorEntry, rk *RekorKey, witness ed25519.PublicKey) (*RekorResult, error) {
	return VerifyRekorBy(e, rk, witness, "witness")
}

// VerifyRekorBy is VerifyRekor for an entry that must have been made by the
// pinned key `signer` names ("witness" for certificate anchors, "dsa-audit"
// for audit roots). The name only appears in error texts.
func VerifyRekorBy(e RekorEntry, rk *RekorKey, key ed25519.PublicKey, signer string) (*RekorResult, error) {
	if rk == nil || rk.Public == nil {
		return nil, errors.New("no Rekor key pinned")
	}
	if len(e.CanonicalBody) == 0 || e.IntegratedTime == 0 {
		return nil, ErrRekorNoBody
	}
	if len(e.SignedEntryTimestamp) == 0 {
		return nil, errors.New("the entry carries no signed entry timestamp")
	}
	if e.LogIndex < 0 {
		return nil, errors.New("negative log index")
	}
	if err := VerifySET(e.CanonicalBody, e.IntegratedTime, e.LogIndex, e.SignedEntryTimestamp, rk); err != nil {
		return nil, err
	}
	res := &RekorResult{IntegratedTime: time.Unix(e.IntegratedTime, 0).UTC()}
	cp, proofIndex, err := verifyInclusion(e.CanonicalBody, e.InclusionProof, rk)
	if err != nil {
		return nil, err
	}
	if proofIndex > e.LogIndex {
		return nil, fmt.Errorf("the inclusion proof's tree index %d is above the signed log index %d (proof is not for this entry)", proofIndex, e.LogIndex)
	}
	res.Checkpoint = cp
	digest, err := verifyHashedRekordBody(e.CanonicalBody, key, signer)
	if err != nil {
		return nil, err
	}
	res.ArtifactSHA512 = digest
	return res, nil
}

// VerifySET checks a Rekor signed entry timestamp.
func VerifySET(body []byte, integratedTime, logIndex int64, set []byte, rk *RekorKey) error {
	// RFC 8785 for this fixed shape: keys in code-point order, integers as
	// plain decimals, and string values that are base64 / lowercase hex
	// (nothing to escape).
	payload := `{"body":"` + base64.StdEncoding.EncodeToString(body) +
		`","integratedTime":` + strconv.FormatInt(integratedTime, 10) +
		`,"logID":"` + rk.LogID +
		`","logIndex":` + strconv.FormatInt(logIndex, 10) + `}`
	d := sha256.Sum256([]byte(payload))
	if !ecdsa.VerifyASN1(rk.Public, d[:], set) {
		return errors.New("signed entry timestamp does not verify under the pinned Rekor key (entry, time or index altered, or not from this log)")
	}
	return nil
}

type inclusionProof struct {
	Checkpoint string
	Hashes     []string
	LogIndex   *int64
	RootHash   string
	TreeSize   *int64
}

// inclusionProofKeys are the keys of Rekor's inclusionProof object, in their
// exact spelling. A proof may lack one (reported below as what is missing);
// it may not carry any other.
var inclusionProofKeys = map[string]bool{"checkpoint": true, "hashes": true, "logIndex": true, "rootHash": true, "treeSize": true}

// proofIntLexeme is a plain non-negative JSON integer: no sign, fraction,
// exponent or leading zero.
var proofIntLexeme = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})$`)

// decodeInclusionProof reads the inclusionProof JSON a bundle carries (for a
// certificate's Rekor entry and for an audit root's) as ONE strict document:
// no duplicate key, no key other than the five above — so no case-variant
// spelling either —, no trailing data, and every value of its JSON type
// (strings, an array of strings, plain integers). The object is unsigned
// bundle content; with a lenient decoder two readers could take different
// values from one byte string (a later duplicate key winning, a case-variant
// key matching a field), so the bytes get exactly one reading here.
//
// The checkpoint VALUE is a signed note in the log's own wire format and is
// parsed as such by VerifyCheckpoint; nothing about it is decided here.
func decodeInclusionProof(proofJSON []byte) (*inclusionProof, error) {
	doc, err := verify.DecodeDocument(proofJSON)
	if err != nil {
		return nil, fmt.Errorf("inclusion proof is not one strict JSON document: %w", err)
	}
	o, ok := doc.(map[string]any)
	if !ok {
		return nil, errors.New("inclusion proof is not a JSON object")
	}
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !inclusionProofKeys[k] {
			return nil, fmt.Errorf("inclusion proof has key %q, which is not a key of a Rekor inclusion proof (keys are case-sensitive)", k)
		}
	}
	p := &inclusionProof{}
	str := func(k string, dst *string) error {
		v, has := o[k]
		if !has {
			return nil
		}
		s, ok := v.(string)
		if !ok {
			return fmt.Errorf("inclusion proof %s is not a string", k)
		}
		*dst = s
		return nil
	}
	num := func(k string, dst **int64) error {
		v, has := o[k]
		if !has {
			return nil
		}
		n, ok := v.(json.Number)
		if !ok || !proofIntLexeme.MatchString(string(n)) {
			return fmt.Errorf("inclusion proof %s is not a plain JSON integer", k)
		}
		i, err := strconv.ParseInt(string(n), 10, 64)
		if err != nil {
			return fmt.Errorf("inclusion proof %s is not a plain JSON integer", k)
		}
		*dst = &i
		return nil
	}
	for _, err := range []error{str("checkpoint", &p.Checkpoint), str("rootHash", &p.RootHash), num("logIndex", &p.LogIndex), num("treeSize", &p.TreeSize)} {
		if err != nil {
			return nil, err
		}
	}
	if v, has := o["hashes"]; has {
		arr, ok := v.([]any)
		if !ok {
			return nil, errors.New("inclusion proof hashes is not an array")
		}
		p.Hashes = make([]string, len(arr))
		for i, h := range arr {
			if p.Hashes[i], ok = h.(string); !ok {
				return nil, fmt.Errorf("inclusion proof hash %d is not a string", i)
			}
		}
	}
	return p, nil
}

// verifyInclusion checks the proof and its REQUIRED signed checkpoint. It
// returns whether the checkpoint verified (always true on a nil error) and
// the proof's tree index.
func verifyInclusion(body, proofJSON []byte, rk *RekorKey) (bool, int64, error) {
	if len(bytes.TrimSpace(proofJSON)) == 0 {
		return false, 0, errors.New("the entry carries no inclusion proof")
	}
	p, err := decodeInclusionProof(proofJSON)
	if err != nil {
		return false, 0, err
	}
	if p.LogIndex == nil || p.TreeSize == nil || p.RootHash == "" {
		return false, 0, errors.New("inclusion proof lacks logIndex, treeSize or rootHash")
	}
	if *p.TreeSize <= 0 || *p.LogIndex < 0 || *p.LogIndex >= *p.TreeSize {
		return false, 0, errors.New("inclusion proof index out of range")
	}
	root, err := hex.DecodeString(p.RootHash)
	if err != nil || len(root) != sha256.Size {
		return false, 0, errors.New("inclusion proof root hash is not 32 hex bytes")
	}
	path := make([][]byte, len(p.Hashes))
	for i, h := range p.Hashes {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != sha256.Size {
			return false, 0, fmt.Errorf("inclusion proof hash %d is not 32 hex bytes", i)
		}
		path[i] = b
	}
	leaf := sha256.Sum256(append([]byte{0x00}, body...))
	got, err := rootFromInclusionProof(uint64(*p.LogIndex), uint64(*p.TreeSize), leaf[:], path)
	if err != nil {
		return false, 0, err
	}
	if !bytes.Equal(got, root) {
		return false, 0, errors.New("inclusion proof does not lead from this entry to the stated root")
	}
	if p.Checkpoint == "" {
		return false, 0, errors.New("inclusion proof carries no signed checkpoint, so its root hash is not signed by the log")
	}
	size, cpRoot, err := VerifyCheckpoint(p.Checkpoint, rk)
	if err != nil {
		return false, 0, err
	}
	if size != uint64(*p.TreeSize) || !bytes.Equal(cpRoot, root) {
		return false, 0, errors.New("the signed checkpoint names a different tree than the inclusion proof")
	}
	return true, *p.LogIndex, nil
}

// rootFromInclusionProof is RFC 9162 § 2.1.3.2.
func rootFromInclusionProof(index, size uint64, leaf []byte, path [][]byte) ([]byte, error) {
	fn, sn := index, size-1
	r := leaf
	for _, p := range path {
		if sn == 0 {
			return nil, errors.New("inclusion proof is longer than the tree allows")
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			if fn&1 == 0 {
				for fn&1 == 0 && fn != 0 {
					fn >>= 1
					sn >>= 1
				}
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return nil, errors.New("inclusion proof is shorter than the tree requires")
	}
	return r, nil
}

func nodeHash(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// VerifyCheckpoint verifies a Rekor checkpoint (a signed note: origin, tree
// size, base64 root hash, then signature lines "— <name> <base64(keyhint ||
// ECDSA signature)>"). The key hint is the first 4 bytes of the log ID. At
// least one signature line must verify under rk over sha256(note text).
func VerifyCheckpoint(cp string, rk *RekorKey) (uint64, []byte, error) {
	i := strings.Index(cp, "\n\n")
	if i < 0 {
		return 0, nil, errors.New("checkpoint has no signature block")
	}
	text := cp[:i+1]
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 {
		return 0, nil, errors.New("checkpoint body is too short")
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return 0, nil, errors.New("checkpoint tree size does not parse")
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(root) != sha256.Size {
		return 0, nil, errors.New("checkpoint root hash does not parse")
	}
	hint, _ := hex.DecodeString(rk.LogID[:8])
	d := sha256.Sum256([]byte(text))
	for _, sl := range strings.Split(cp[i+2:], "\n") {
		if !strings.HasPrefix(sl, "— ") {
			continue
		}
		f := strings.Fields(strings.TrimPrefix(sl, "— "))
		if len(f) != 2 {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(f[1])
		if err != nil || len(raw) < 5 || !bytes.Equal(raw[:4], hint) {
			continue
		}
		if ecdsa.VerifyASN1(rk.Public, d[:], raw[4:]) {
			return size, root, nil
		}
		return 0, nil, errors.New("checkpoint signature does not verify under the pinned Rekor key")
	}
	return 0, nil, errors.New("checkpoint carries no signature by the pinned Rekor key")
}

type hashedRekord struct {
	Kind       string `json:"kind"`
	APIVersion string `json:"apiVersion"`
	Spec       struct {
		Data struct {
			Hash struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"hash"`
		} `json:"data"`
		Signature struct {
			Content   string `json:"content"`
			PublicKey struct {
				Content string `json:"content"`
			} `json:"publicKey"`
		} `json:"signature"`
	} `json:"spec"`
}

// verifyHashedRekordBody checks that the logged entry was made by the pinned
// key (the witness key for certificate anchors): its public key is that key,
// and its Ed25519ph signature over the logged SHA-512 digest verifies.
// Returns the digest (hex). signer names the key in error texts.
func verifyHashedRekordBody(body []byte, witness ed25519.PublicKey, signer string) (string, error) {
	var hr hashedRekord
	if err := json.Unmarshal(body, &hr); err != nil {
		return "", fmt.Errorf("Rekor entry body does not parse: %w", err)
	}
	if hr.Kind != "hashedrekord" || hr.APIVersion != "0.0.1" {
		return "", fmt.Errorf("Rekor entry is %s/%s, not hashedrekord/0.0.1", hr.Kind, hr.APIVersion)
	}
	if hr.Spec.Data.Hash.Algorithm != "sha512" {
		return "", fmt.Errorf("Rekor entry hash algorithm is %q, not sha512", hr.Spec.Data.Hash.Algorithm)
	}
	digest, err := hex.DecodeString(hr.Spec.Data.Hash.Value)
	if err != nil || len(digest) != 64 {
		return "", errors.New("Rekor entry digest is not 64 hex bytes")
	}
	pemBytes, err := base64.StdEncoding.DecodeString(hr.Spec.Signature.PublicKey.Content)
	if err != nil {
		return "", errors.New("Rekor entry public key is not base64")
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return "", errors.New("Rekor entry public key is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", errors.New("Rekor entry public key does not parse")
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok || !bytes.Equal(ed, witness) {
		return "", fmt.Errorf("Rekor entry was not logged by the pinned %s key", signer)
	}
	sig, err := base64.StdEncoding.DecodeString(hr.Spec.Signature.Content)
	if err != nil {
		return "", errors.New("Rekor entry signature is not base64")
	}
	if err := ed25519.VerifyWithOptions(witness, digest, sig, &ed25519.Options{Hash: crypto.SHA512}); err != nil {
		return "", fmt.Errorf("the %s signature inside the Rekor entry does not verify", signer)
	}
	return hr.Spec.Data.Hash.Value, nil
}
