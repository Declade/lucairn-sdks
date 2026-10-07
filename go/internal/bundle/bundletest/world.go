// Package bundletest builds SYNTHETIC evidence bundles for the lucairn-bundle-verify
// tests and tamper corpus: its own witness, service, TSA and Rekor keys, its
// own certificates and anchors. Nothing here is production data, and nothing
// here is reachable from the lucairn-bundle-verify binary.
package bundletest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/anchor"
	"github.com/declade/lucairn-sdks/go/internal/bundle"
	"github.com/declade/lucairn-sdks/go/internal/verify"
)

// WitnessKeyID is the synthetic witness key id.
const WitnessKeyID = "witness_synthetic_v1"

// CorpusCutover is the synthetic world's anchor-binding cutover: certificates
// issued after it must carry binding-v1 anchors (T-1231 S2a downgrade guard).
var CorpusCutover = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// World is one synthetic deployment.
type World struct {
	Witness  ed25519.PrivateKey
	Services map[string]ed25519.PrivateKey
	TSARoot  *x509.Certificate
	TSALeaf  *x509.Certificate
	tsaKey   *ecdsa.PrivateKey
	Rekor    *ecdsa.PrivateKey
	rekorKey *anchor.RekorKey
	seq      int
	// rootEntries numbers the synthetic log's audit-root entries.
	rootEntries int
}

func edKey(seed string) ed25519.PrivateKey {
	h := sha256.Sum256([]byte("lucairn-bundle-verify synthetic " + seed))
	return ed25519.NewKeyFromSeed(h[:])
}

// NewWorld builds a synthetic deployment. ECDSA keys are generated fresh
// (crypto/ecdsa does not take a deterministic reader); Ed25519 keys are
// derived from seed.
func NewWorld(seed string) (*World, error) { return NewWorldWith(seed, WorldOptions{}) }

// WorldOptions bend a synthetic world for negative tests.
type WorldOptions struct {
	// TSAEKUNonCritical issues the TSA certificate with a NON-critical
	// time-stamping EKU (violates RFC 3161 § 2.3).
	TSAEKUNonCritical bool
}

// NewWorldWith builds a synthetic deployment with options.
func NewWorldWith(seed string, wo WorldOptions) (*World, error) {
	w := &World{
		Witness: edKey(seed + "/witness"),
		Services: map[string]ed25519.PrivateKey{
			"dsa-bridge":    edKey(seed + "/dsa-bridge"),
			"dsa-sanitizer": edKey(seed + "/dsa-sanitizer"),
			"dsa-gateway":   edKey(seed + "/dsa-gateway"),
			"dsa-ai":        edKey(seed + "/dsa-ai"),
			// The audit service's claim key; it also signs audit roots (S2b).
			AuditService: edKey(seed + "/dsa-audit"),
		},
	}
	var err error
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Synthetic TSA Root (test only)"},
		NotBefore:             notBefore,
		NotAfter:              notBefore.AddDate(20, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	w.TSARoot, _ = x509.ParseCertificate(rootDER)
	w.tsaKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Synthetic TSA (test only)"},
		NotBefore:    notBefore,
		NotAfter:     notBefore.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		// RFC 3161 § 2.3: exactly one EKU (time stamping), marked CRITICAL.
		// Go's ExtKeyUsage field emits a non-critical extension, which
		// `openssl ts -verify` rightly rejects; ExtraExtensions overrides it.
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: seq(oid(asn1OID(1, 3, 6, 1, 5, 5, 7, 3, 8)))}},
	}
	if wo.TSAEKUNonCritical {
		leafTmpl.ExtraExtensions = nil
		leafTmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, w.TSARoot, &w.tsaKey.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	w.TSALeaf, _ = x509.ParseCertificate(leafDER)
	w.Rekor, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	w.rekorKey, err = anchor.ParseRekorKeyPEM(w.RekorPEM())
	if err != nil {
		return nil, err
	}
	return w, nil
}

// RekorPEM is the synthetic Rekor public key.
func (w *World) RekorPEM() []byte {
	der, _ := x509.MarshalPKIXPublicKey(&w.Rekor.PublicKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// TSARootPEM is the synthetic TSA root certificate.
func (w *World) TSARootPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.TSARoot.Raw})
}

// TSALeafPEM is the TSA signing certificate (for openssl ts -verify -untrusted).
func (w *World) TSALeafPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.TSALeaf.Raw})
}

// Roots returns the trust roots that verify this world's bundles.
func (w *World) Roots() bundle.TrustRoots {
	pool := x509.NewCertPool()
	pool.AddCert(w.TSARoot)
	svc := map[string]ed25519.PublicKey{}
	for id, k := range w.Services {
		svc[id] = k.Public().(ed25519.PublicKey)
	}
	return bundle.TrustRoots{
		WitnessKeys: map[string]ed25519.PublicKey{WitnessKeyID: w.Witness.Public().(ed25519.PublicKey)},
		ServiceKeys: svc,
		TSARoots:    pool,
		Rekor:       w.rekorKey,
		Label:       "SYNTHETIC test roots",
		// The synthetic world's cutover (the corpus measures the hosted
		// policy, whose roots carry the real one).
		BindingRequiredAfter: CorpusCutover,
		CleaningRequiredFrom: CorpusCleaningStart,
	}
}

// CorpusCleaningStart is independent of the hosted pin and the wall clock.
// It predates the legacy-anchor PARTIAL controls in the cleaning corpus.
var CorpusCleaningStart = CorpusCutover.Add(-24 * time.Hour)

// CLIFlags are the lucairn-bundle-verify flags that trust this world, given the
// paths the root PEMs were written to.
func (w *World) CLIFlags(tsaRootPath, rekorKeyPath string) []string {
	out := []string{"--witness-key", WitnessKeyID + "=" + base64.StdEncoding.EncodeToString(w.Witness.Public().(ed25519.PublicKey))}
	for _, id := range []string{"dsa-bridge", "dsa-sanitizer", "dsa-gateway", "dsa-ai", AuditService} {
		out = append(out, "--service-key", id+"="+base64.StdEncoding.EncodeToString(w.Services[id].Public().(ed25519.PublicKey)))
	}
	// --require-anchors: the corpus measures the Lucairn-hosted policy (every
	// certificate must be anchored), which a custom witness key turns off.
	// --require-binding-after: the same for the anchor-binding cutover.
	// --require-anchors stays LAST (tests strip it to get the custom policy).
	return append(out, "--tsa-root", tsaRootPath, "--rekor-key", rekorKeyPath,
		"--require-binding-after", CorpusCutover.Format(time.RFC3339),
		"--require-cleaning-from", CorpusCleaningStart.Format(time.RFC3339), "--require-anchors")
}

// LeafHashHex is the RFC 6962 leaf hash of b (hex) — what an inclusion proof
// for an entry with body b starts from.
func LeafHashHex(b []byte) string { return hex.EncodeToString(leafHash(b)) }

// Cert is one synthetic certificate.
type Cert struct {
	RequestID     string
	CertificateID string
	IssuedAt      time.Time
	JSON          []byte
	// Raw stands in for the witness's stored certificate bytes: cert_hash is
	// sha256(Raw). Legacy anchors: the TSA imprint is sha256(Raw) and the
	// Rekor entry logs sha512(Raw). Bound (binding v1) anchors: both commit
	// to H = anchor.DigestV1(sha256(Raw), signed v3 signable).
	Raw []byte
	Doc map[string]any
	// H is the binding-v1 digest the anchors commit to (Bound certificates
	// only; nil otherwise).
	H []byte
	// Event is the counted audit event of this request (CertOptions.Audit
	// without Uncounted; nil otherwise).
	Event *bundle.AuditEvent
}

// CertOptions shape one certificate.
type CertOptions struct {
	// Cleaning replaces the ordinary claims with sanitizer + gateway claims.
	Cleaning       *CleaningOptions
	ConversationID string
	CustomerID     string
	IssuedAt       time.Time
	// AnchorAt is when the anchors were obtained (zero = IssuedAt + 2 s).
	AnchorAt time.Time
	// NoAnchors leaves the attestation empty (a self-hosted, unanchored cert).
	NoAnchors bool
	// Bound anchors the certificate with anchor binding v1 (the S2a witness).
	Bound bool
	// Audit, when set, records the request's terminal audit event in this
	// synthetic audit log and adds the dsa-audit EVENTS_RECORDED claim that
	// signs its event_hash (T-1231 S2b). The event is COUNTED (v2 hash with
	// conversation_id + conv_seq) unless Uncounted.
	Audit *AuditLog
	// Uncounted records the event as a row from before counting started (v1
	// hash, no counter entry); the claim still signs its event_hash.
	Uncounted bool
	// NoSignedCounter leaves conversation_id + conv_seq OUT of the signed
	// audit claim payload of a counted request. The audit service always
	// signs them (design D3); a certificate without them is "not tracked", even
	// when the bundle lists a counter entry with its event_hash.
	NoSignedCounter bool
	// ExtraAuditSeq, when not 0, adds a SECOND valid dsa-audit EVENTS_RECORDED
	// claim for the same audit row (same event_hash) that signs this other
	// conv_seq: a certificate with two signed counter claims.
	ExtraAuditSeq uint64
}

// NewCert mints one fully signed, anchored certificate.
func (w *World) NewCert(o CertOptions) (*Cert, error) {
	w.seq++
	n := w.seq
	reqID := fmt.Sprintf("%032x", sha256.Sum256([]byte(fmt.Sprintf("req/%s/%d", o.ConversationID, n))))[:32]
	certID := fmt.Sprintf("veil_synthetic-%04d-%s", n, reqID[:8])
	claimID := fmt.Sprintf("clm_synthetic-%04d", n)
	issued := o.IssuedAt.UTC()
	issuedStr := issued.Format(time.RFC3339Nano) // the witness signs the RFC3339Nano form
	claimTS := issued.Add(-3 * time.Second).Format("2006-01-02T15:04:05.000000000Z")

	payload := map[string]any{
		"api_key_id":      "key_synthetic",
		"conversation_id": o.ConversationID,
		"customer_id":     o.CustomerID,
		"ephemeral":       true,
		"org_id":          "",
	}
	dataSeen := []string{"customer_id"}
	dataNotSeen := []string{"context", "prompt_template", "inference_result"}
	canon, err := verify.CanonicalLexeme(map[string]any{
		"claim_id": claimID, "request_id": reqID, "service_id": "dsa-bridge",
		"claim_type": "TOKEN_GENERATED", "data_seen": dataSeen, "data_not_seen": dataNotSeen,
		"payload": payload, "timestamp": claimTS,
	})
	if err != nil {
		return nil, err
	}
	claim := map[string]any{
		"claim_id":          claimID,
		"request_id":        reqID,
		"service_id":        "dsa-bridge",
		"claim_type":        "CLAIM_TYPE_TOKEN_GENERATED",
		"data_seen":         dataSeen,
		"data_not_seen":     dataNotSeen,
		"canonical_payload": base64.StdEncoding.EncodeToString(canon),
		"signature":         base64.StdEncoding.EncodeToString(ed25519.Sign(w.Services["dsa-bridge"], canon)),
		"timestamp":         claimTS,
	}
	claimIDs, claims := []any{claimID}, []any{claim}
	var event *bundle.AuditEvent
	if o.Cleaning != nil {
		cleaning, err := w.cleaningClaims(o, n, reqID, claimTS)
		if err != nil {
			return nil, err
		}
		claimIDs, claims = nil, nil
		for _, c := range cleaning {
			claimIDs, claims = append(claimIDs, c["claim_id"]), append(claims, c)
		}
		if o.Audit != nil {
			e := syntheticEvent(o.ConversationID, reqID, o.CustomerID)
			e.EventType = "SENSITIVE_MODE_CERT_SEALED"
			e.EventID = "evt_seal_" + reqID
			if o.Cleaning.EventType != "" {
				e.EventType = o.Cleaning.EventType
			}
			e = o.Audit.record(e)
			event = &e
		}
	} else if o.Audit != nil {
		acs, ev, err := w.auditClaim(o, n, reqID, issued)
		if err != nil {
			return nil, err
		}
		for _, ac := range acs {
			claimIDs, claims = append(claimIDs, ac["claim_id"]), append(claims, ac)
		}
		event = ev
	}
	verdict := "VERIFIED"
	if o.Cleaning != nil && o.Cleaning.SealedPartial {
		verdict = "PARTIAL"
	}
	v2 := map[string]any{
		"certificate_id": certID, "request_id": reqID, "protocol_version": json.Number("2"),
		"claim_ids": claimIDs, "issued_at": issuedStr,
		"overall_verdict": verdict, "witness_key_id": WitnessKeyID,
	}
	v2b, _ := verify.CanonicalLexeme(v2)
	v3 := map[string]any{}
	for k, v := range v2 {
		v3[k] = v
	}
	v3["client_id"] = nil
	v3["api_key_id"] = "key_synthetic"
	v3["byok_exempt"] = false
	v3["redaction_manifest_hash"] = nil
	v3["sanitized_fields_body_hash"] = nil
	v3["tms_manifest_hash"] = nil
	v3b, _ := verify.CanonicalLexeme(v3)
	v2sig := base64.StdEncoding.EncodeToString(ed25519.Sign(w.Witness, v2b))
	v3sig := base64.StdEncoding.EncodeToString(ed25519.Sign(w.Witness, v3b))

	doc := map[string]any{
		"certificate_id":   certID,
		"request_id":       reqID,
		"protocol_version": 2,
		"claims":           claims,
		"verification": map[string]any{
			"overall_verdict": "VERDICT_" + verdict,
			"byok_exempt":     false,
		},
		"witness_signature":                 v2sig,
		"witness_key_id":                    WitnessKeyID,
		"issued_at":                         issuedStr,
		"signable_v2_signature":             v2sig,
		"signable_v3_signature":             v3sig,
		"signable_protocol_version_emitted": 3,
		"client_id":                         nil,
		"api_key_id":                        "key_synthetic",
		"conversation_id":                   o.ConversationID,
		"attestation":                       map[string]any{},
		"anchor_status":                     map[string]any{"status": "ANCHOR_STATUS_PENDING"},
	}
	raw := []byte("synthetic certificate_raw stand-in for " + certID + " issued " + issuedStr)
	c := &Cert{RequestID: reqID, CertificateID: certID, IssuedAt: issued, Raw: raw, Doc: doc, Event: event}
	if !o.NoAnchors {
		at := o.AnchorAt
		if at.IsZero() {
			at = issued.Add(2 * time.Second)
		}
		digest := sha256.Sum256(raw)
		imprint, artifact, marker := digest[:], raw, anchor.HashAlgorithmLegacy
		if o.Bound {
			h := anchor.DigestV1(digest[:], v3b)
			imprint, artifact, marker = h, h, anchor.HashAlgorithmV1
			c.H = h
		}
		tok, err := w.Timestamp(imprint, at)
		if err != nil {
			return nil, err
		}
		tl, err := w.rekorEntry(artifact, at, int64(1000+n))
		if err != nil {
			return nil, err
		}
		doc["attestation"] = map[string]any{
			"timestamp": map[string]any{
				"provider":        "https://tsa.synthetic.invalid/tsr",
				"timestamp_token": base64.StdEncoding.EncodeToString(tok),
				"cert_hash":       base64.StdEncoding.EncodeToString(digest[:]),
				"hash_algorithm":  marker,
			},
			"transparency_log": tl,
		}
		doc["anchor_status"] = map[string]any{"status": "ANCHOR_STATUS_ANCHORED", "attempts": 1}
	}
	if o.Cleaning != nil {
		doc["verification"].(map[string]any)["cert_tier"] = "input_shield_two_signer"
		if o.Cleaning.UnsignedTier != "" {
			doc["verification"].(map[string]any)["cert_tier"] = o.Cleaning.UnsignedTier
		}
	}
	if err := c.Remarshal(); err != nil {
		return nil, err
	}
	return c, nil
}

// Remarshal re-serializes Doc into JSON (after a test edits Doc).
func (c *Cert) Remarshal() error {
	b, err := json.MarshalIndent(c.Doc, "", "  ")
	if err != nil {
		return err
	}
	c.JSON = b
	return nil
}

// ---- RFC 3161 ----

// Timestamp issues a synthetic RFC 3161 TimeStampResp over digest at genTime.
func (w *World) Timestamp(digest []byte, genTime time.Time) ([]byte, error) {
	tst := seq(
		integer(1),
		oid(asn1OID(1, 3, 6, 1, 4, 1, 99999, 1)),
		seq(seq(oid(asn1OID(2, 16, 840, 1, 101, 3, 4, 2, 1)), null()), octet(digest)),
		integer(int64(genTime.UnixNano()&0x7fffffff)),
		generalizedTime(genTime),
	)
	md := sha256.Sum256(tst)
	leafHash := sha256.Sum256(w.TSALeaf.Raw)
	attrs := sortedSetBody(
		seq(oid(asn1OID(1, 2, 840, 113549, 1, 9, 3)), set(oid(asn1OID(1, 2, 840, 113549, 1, 9, 16, 1, 4)))),
		seq(oid(asn1OID(1, 2, 840, 113549, 1, 9, 4)), set(octet(md[:]))),
		seq(oid(asn1OID(1, 2, 840, 113549, 1, 9, 16, 2, 47)), set(seq(seq(seq(octet(leafHash[:])))))),
	)
	signedSet := tlv(0x31, attrs)
	h := sha256.Sum256(signedSet)
	sig, err := ecdsa.SignASN1(rand.Reader, w.tsaKey, h[:])
	if err != nil {
		return nil, err
	}
	si := seq(
		integer(1),
		seq(w.TSALeaf.RawIssuer, integerBig(w.TSALeaf.SerialNumber)),
		seq(oid(asn1OID(2, 16, 840, 1, 101, 3, 4, 2, 1)), null()),
		tlv(0xa0, attrs),
		seq(oid(asn1OID(1, 2, 840, 10045, 4, 3, 2))),
		octet(sig),
	)
	sd := seq(
		integer(3),
		set(seq(oid(asn1OID(2, 16, 840, 1, 101, 3, 4, 2, 1)), null())),
		seq(oid(asn1OID(1, 2, 840, 113549, 1, 9, 16, 1, 4)), tlv(0xa0, octet(tst))),
		tlv(0xa0, w.TSALeaf.Raw),
		set(si),
	)
	token := seq(oid(asn1OID(1, 2, 840, 113549, 1, 7, 2)), tlv(0xa0, sd))
	return seq(seq(integer(0)), token), nil
}

// ---- Rekor ----

func (w *World) rekorEntry(raw []byte, at time.Time, logIndex int64) (map[string]any, error) {
	return w.rekorEntryBy(w.Witness, raw, at, logIndex)
}

// rekorEntryBy logs sha512(raw) in the synthetic Rekor as a hashedrekord made
// by key (the witness for certificate anchors, the audit key for audit
// roots, or any other key: a public log accepts entries from anyone).
func (w *World) rekorEntryBy(key ed25519.PrivateKey, raw []byte, at time.Time, logIndex int64) (map[string]any, error) {
	digest := sha512.Sum512(raw)
	sig, err := key.Sign(rand.Reader, digest[:], crypto.SHA512)
	if err != nil {
		return nil, err
	}
	der, _ := x509.MarshalPKIXPublicKey(key.Public())
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	body, err := verify.CanonicalLexeme(map[string]any{
		"apiVersion": "0.0.1", "kind": "hashedrekord",
		"spec": map[string]any{
			"data":      map[string]any{"hash": map[string]any{"algorithm": "sha512", "value": hex.EncodeToString(digest[:])}},
			"signature": map[string]any{"content": base64.StdEncoding.EncodeToString(sig), "publicKey": map[string]any{"content": base64.StdEncoding.EncodeToString(pubPEM)}},
		},
	})
	if err != nil {
		return nil, err
	}
	return w.logBody(body, at, logIndex)
}

// LogBody logs an already-built hashedrekord body in the synthetic Rekor and
// returns the entry in the verifier's input form.
func (w *World) LogBody(body []byte, at time.Time, logIndex int64) (anchor.RekorEntry, error) {
	tl, err := w.logBody(body, at, logIndex)
	if err != nil {
		return anchor.RekorEntry{}, err
	}
	dec := func(k string) []byte {
		b, _ := base64.StdEncoding.DecodeString(tl[k].(string))
		return b
	}
	return anchor.RekorEntry{LogIndex: logIndex, IntegratedTime: at.Unix(), CanonicalBody: body,
		SignedEntryTimestamp: dec("signed_entry_timestamp"), InclusionProof: dec("inclusion_proof")}, nil
}

// logBody puts body into a small synthetic log tree and signs the entry
// (SET, inclusion proof, checkpoint) with the synthetic log key.
func (w *World) logBody(body []byte, at time.Time, logIndex int64) (map[string]any, error) {
	// A small tree: filler leaves around ours.
	leaves := [][]byte{}
	pos := int(logIndex % 5)
	for i := 0; i < 7; i++ {
		if i == pos {
			leaves = append(leaves, leafHash(body))
			continue
		}
		leaves = append(leaves, leafHash([]byte(fmt.Sprintf("filler %d %d", logIndex, i))))
	}
	root := mth(leaves)
	path := inclusionPath(pos, leaves)
	hashes := make([]string, len(path))
	for i, p := range path {
		hashes[i] = hex.EncodeToString(p)
	}
	note := fmt.Sprintf("rekor.synthetic.invalid - 1\n%d\n%s\n", len(leaves), base64.StdEncoding.EncodeToString(root))
	nd := sha256.Sum256([]byte(note))
	nsig, err := ecdsa.SignASN1(rand.Reader, w.Rekor, nd[:])
	if err != nil {
		return nil, err
	}
	hint, _ := hex.DecodeString(w.rekorKey.LogID[:8])
	checkpoint := note + "\n— rekor.synthetic.invalid " + base64.StdEncoding.EncodeToString(append(hint, nsig...)) + "\n"
	proof, _ := json.Marshal(map[string]any{
		"checkpoint": checkpoint, "hashes": hashes, "logIndex": pos, "rootHash": hex.EncodeToString(root), "treeSize": len(leaves),
	})
	itime := at.Unix()
	set, err := w.SET(body, itime, logIndex)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"provider":               "https://rekor.synthetic.invalid",
		"log_index":              strconv.FormatInt(logIndex, 10),
		"inclusion_proof":        base64.StdEncoding.EncodeToString(proof),
		"signed_entry_timestamp": base64.StdEncoding.EncodeToString(set),
		"log_url":                "https://rekor.synthetic.invalid",
		"canonical_body":         base64.StdEncoding.EncodeToString(body),
		"integrated_time":        strconv.FormatInt(itime, 10),
	}, nil
}

// SET signs a Rekor signed entry timestamp with the synthetic log key.
func (w *World) SET(body []byte, integratedTime, logIndex int64) ([]byte, error) {
	payload := `{"body":"` + base64.StdEncoding.EncodeToString(body) + `","integratedTime":` +
		strconv.FormatInt(integratedTime, 10) + `,"logID":"` + w.rekorKey.LogID + `","logIndex":` +
		strconv.FormatInt(logIndex, 10) + `}`
	d := sha256.Sum256([]byte(payload))
	return ecdsa.SignASN1(rand.Reader, w.Rekor, d[:])
}

func leafHash(b []byte) []byte {
	h := sha256.Sum256(append([]byte{0}, b...))
	return h[:]
}

func node(l, r []byte) []byte {
	h := sha256.New()
	h.Write([]byte{1})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

func split(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func mth(leaves [][]byte) []byte {
	if len(leaves) == 1 {
		return leaves[0]
	}
	k := split(len(leaves))
	return node(mth(leaves[:k]), mth(leaves[k:]))
}

func inclusionPath(m int, leaves [][]byte) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := split(len(leaves))
	if m < k {
		return append(inclusionPath(m, leaves[:k]), mth(leaves[k:]))
	}
	return append(inclusionPath(m-k, leaves[k:]), mth(leaves[:k]))
}
