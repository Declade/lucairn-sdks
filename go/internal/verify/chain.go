package verify

// Certificate chain verification (T-935 S3 / T-794) — every inner claim.
//
// Run (pipeline.go) checks the witness signatures only: a certificate whose
// claim body was edited while its claim id stayed the same still passes it,
// because the witness signs the claim-id LIST, not the claim content. RunChain
// adds the layer on top: every claim's own Ed25519 signature against a PINNED
// per-service key, the canonical bytes rebuilt from the outer fields,
// claim-id membership in the witness-signed list, the typed (unsigned)
// mirrors against the signed payload, the signed egress digests, the unsigned
// cert_tier against its signed copies, and the user_unredacted_segment token
// read from the SIGNED sanitizer payload only.
//
// The specification is the parity corpus README (Declade/dual-sandbox-
// architecture tools/parity-corpus/README.md; its ordered check table is
// vendored at testdata/parity-corpus/recipe-table.md) § Verification recipe; this is a port of its
// Go reference (services/veil-witness/internal/paritycorpus/reference_test.go).
// The TS and Python SDKs implement the same table; all three are held to the
// same corpus under both policies.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// ChainStep is one row of the recipe table: the step id, and the verdict +
// reason a certificate gets when that step decides it.
type ChainStep struct {
	ID, Verdict, Reason string
}

// ChainSteps — THE ordered check list (README § Verification recipe,
// recipe-table). parity_corpus_test.go asserts it equals the vendored recipe-table.md.
var ChainSteps = []ChainStep{
	{"1", "FAILED", "malformed"},
	{"2", "FAILED", "unsupported_protocol_version"},
	{"3", "FAILED", "witness_key_mismatch"},
	{"4", "FAILED", "version_downgrade_detected"},
	{"5a", "FAILED", "malformed"},
	{"5b", "FAILED", "witness_signature_invalid"},
	{"5c", "FAILED", "witness_signature_invalid"},
	{"5d", "FAILED", "signable_version_insufficient"},
	{"6a", "FAILED", "sealed_failed"},
	{"6b", "FAILED", "malformed"},
	{"6c", "FAILED", "duplicate_claim_id"},
	{"7a", "FAILED", "unknown_service"},
	{"7b", "FAILED", "malformed"},
	{"7c", "FAILED", "service_key_mismatch"},
	{"7d", "FAILED", "claim_signature_invalid"},
	{"7e", "FAILED", "claim_canonical_mismatch"},
	{"7f", "FAILED", "claim_not_witness_listed"},
	{"7g", "FAILED", "claim_canonical_mismatch"},
	{"7h", "FAILED", "request_id_splice"},
	{"7i", "FAILED", "typed_payload_mismatch"},
	{"8a", "FAILED", "egress_digest_malformed"},
	{"8b", "FAILED", "egress_body_unbound"},
	{"8c", "FAILED", "egress_body_hash_mismatch"},
	{"8d", "FAILED", "cert_tier_mismatch"},
	{"9a", "PARTIAL", "inference_unfinished"},
	{"9b", "PARTIAL", "user_sent_unredacted"},
	{"9c", "PARTIAL", "sealed_partial"},
	{"9d", "EGRESS_UNATTESTED", "egress_unattested"},
	{"9e", "VERIFIED", "ok"},
}

// ChainKeys are the pinned trust roots, already normalized to raw Ed25519 keys.
type ChainKeys struct {
	WitnessKeyID string
	Witness      ed25519.PublicKey
	Services     map[string]ed25519.PublicKey
}

// ChainResult — README § Result.
type ChainResult struct {
	Verdict               string
	Reason                string
	EgressAttestation     string
	UserUnredacted        string
	SignedCertTier        string
	SignableVersion       string
	AuthenticatedFields   []string
	UnauthenticatedFields []string
}

var (
	chainV2Fields          = []string{"certificate_id", "claim_ids", "issued_at", "overall_verdict", "protocol_version", "request_id", "witness_key_id"}
	chainV3Only            = []string{"api_key_id", "byok_exempt", "client_id", "redaction_manifest_hash", "sanitized_fields_body_hash", "tms_manifest_hash"}
	chainDisplayedV3Only   = []string{"api_key_id", "byok_exempt", "client_id"}
	chainLowerHex64        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	chainIntegerToken      = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
	chainTimestampGrammar  = regexp.MustCompile(`^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d{1,9}))?(Z|([+-])(\d\d):(\d\d))$`)
	chainUserUnredactedTok = "user_unredacted_segment"
)

// MaxChainDepth bounds nesting (arrays/objects; brackets inside strings do not
// count). The TS and Python SDKs enforce the same bound, so all three decide
// deep documents alike; real certificates nest fewer than 10 levels.
const MaxChainDepth = 256

// chainIntegerMaxDigits = len("18446744073709551615"): a longer token is out
// of range before any conversion.
const chainIntegerMaxDigits = 20

func chainStep(id string) ChainStep {
	for _, s := range ChainSteps {
		if s.ID == id {
			return s
		}
	}
	panic("verify: step " + id + " is not in ChainSteps")
}

type chainPass struct {
	egress, sv, userUnredacted, tier string
	typedUnauth                      []string
}

func chainDecide(id string, st chainPass) ChainResult {
	s := chainStep(id)
	if s.Verdict == "FAILED" {
		return ChainResult{
			Verdict: "FAILED", Reason: s.Reason, EgressAttestation: "not_evaluated",
			UserUnredacted: "unknown", SignedCertTier: "not_evaluated", SignableVersion: "none",
			AuthenticatedFields:   []string{},
			UnauthenticatedFields: append([]string{}, chainDisplayedV3Only...),
		}
	}
	var auth, unauth []string
	if st.sv == "v3" {
		auth = append(append([]string{}, chainV2Fields...), chainV3Only...)
		sort.Strings(auth)
		unauth = []string{}
	} else {
		auth = append([]string{}, chainV2Fields...)
		unauth = append([]string{}, chainDisplayedV3Only...)
	}
	unauth = append(unauth, st.typedUnauth...)
	sort.Strings(unauth)
	return ChainResult{
		Verdict: s.Verdict, Reason: s.Reason, EgressAttestation: st.egress,
		UserUnredacted: st.userUnredacted, SignedCertTier: st.tier, SignableVersion: st.sv,
		AuthenticatedFields: auth, UnauthenticatedFields: unauth,
	}
}

var chainNo = chainPass{}

// DecodeDocument parses README § Input document: valid UTF-8 (Go's decoder
// would otherwise replace invalid bytes with U+FFFD), at most MaxChainDepth
// levels, exactly one JSON value with number lexemes kept (json.Number), then
// only whitespace up to EOF. dec.More() is NOT enough: it reports false
// before a stray ']' or '}'. An escaped UTF-16 surrogate that is not part of
// a pair decodes as U+FFFD (encoding/json); the TS and Python SDKs do the same.
func DecodeDocument(b []byte) (any, error) {
	if !utf8.Valid(b) {
		return nil, fmt.Errorf("not UTF-8")
	}
	if !depthOK(b) {
		return nil, fmt.Errorf("nesting deeper than %d", MaxChainDepth)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("trailing data after the document")
	}
	return v, nil
}

// CanonicalLexeme encodes v as Python json.dumps(sort_keys=True,
// separators=(",", ":"), ensure_ascii=True) with json.Number lexemes kept
// (README § Canonical JSON). Types: nil, bool, string, json.Number, []any,
// []string, map[string]any.
func CanonicalLexeme(v any) ([]byte, error) {
	return appendLexeme(nil, v)
}

func appendLexeme(dst []byte, v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return append(dst, "null"...), nil
	case bool:
		if x {
			return append(dst, "true"...), nil
		}
		return append(dst, "false"...), nil
	case string:
		return appendPythonAsciiString(dst, x), nil
	case json.Number:
		return append(dst, x.String()...), nil
	case []string:
		dst = append(dst, '[')
		for i, s := range x {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendPythonAsciiString(dst, s)
		}
		return append(dst, ']'), nil
	case []any:
		dst = append(dst, '[')
		for i, item := range x {
			if i > 0 {
				dst = append(dst, ',')
			}
			var err error
			if dst, err = appendLexeme(dst, item); err != nil {
				return nil, err
			}
		}
		return append(dst, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // bytewise over UTF-8 = code-point order
		dst = append(dst, '{')
		for i, k := range keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendPythonAsciiString(dst, k)
			dst = append(dst, ':')
			var err error
			if dst, err = appendLexeme(dst, x[k]); err != nil {
				return nil, err
			}
		}
		return append(dst, '}'), nil
	default:
		return nil, fmt.Errorf("canonical: unsupported type %T", v)
	}
}

// depthOK reports whether b nests at most MaxChainDepth arrays/objects,
// skipping brackets inside strings.
func depthOK(b []byte) bool {
	depth := 0
	inStr, esc := false, false
	for _, c := range b {
		switch {
		case inStr:
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '[' || c == '{':
			depth++
			if depth > MaxChainDepth {
				return false
			}
		case c == ']' || c == '}':
			depth--
		}
	}
	return true
}

func chainStrList(v any) ([]string, bool) {
	if v == nil {
		return []string{}, true
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(arr))
	for i, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

// chainB64 decodes CANONICAL standard padded base64 (step 7b); absent/null →
// empty. The string must be exactly the standard encoding of its bytes.
func chainB64(v any) ([]byte, bool) {
	if v == nil {
		return []byte{}, true
	}
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || base64.StdEncoding.EncodeToString(b) != s {
		return nil, false
	}
	return b, true
}

func chainOptString(v any) (string, bool) {
	if v == nil {
		return "", true
	}
	s, ok := v.(string)
	return s, ok
}

func chainUintToken(s string, max uint64) (uint64, bool) {
	if len(s) > chainIntegerMaxDigits || !chainIntegerToken.MatchString(s) {
		return 0, false
	}
	u, err := strconv.ParseUint(s, 10, 64)
	return u, err == nil && u <= max
}

// ChainInteger reads a JSON number written as an integer TOKEN (digits only),
// in [0, max].
func ChainInteger(v any, max uint64) (uint64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	return chainUintToken(n.String(), max)
}

func chainTypedUint(v any) (uint64, bool) {
	switch x := v.(type) {
	case nil:
		return 0, true
	case string:
		return chainUintToken(x, math.MaxUint64)
	default:
		return ChainInteger(v, math.MaxUint64)
	}
}

// ChainFloat32 reads a JSON number rounded to float32; out of range (beyond
// float64, or ±Inf as a float32) never matches.
func ChainFloat32(v any, zeroIfAbsent bool) (float32, bool) {
	if v == nil && zeroIfAbsent {
		return 0, true
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	f, err := n.Float64()
	if err != nil {
		return 0, false
	}
	g := float32(f)
	if math.IsInf(float64(g), 0) {
		return 0, false
	}
	return g, true
}

// ChainIssuedAt applies README step 5a (the ONE timestamp grammar) and returns
// the UTC RFC3339Nano form.
func ChainIssuedAt(s string) (string, bool) {
	m := chainTimestampGrammar.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	if m[9] != "" {
		oh, _ := strconv.Atoi(m[10])
		om, _ := strconv.Atoi(m[11])
		if oh > 23 || om > 59 {
			return "", false
		}
	}
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil || ts.Year() < 1 {
		return "", false
	}
	u := ts.UTC()
	if u.Year() < 1 || u.Year() > 9999 {
		return "", false
	}
	return u.Format(time.RFC3339Nano), true
}

func chainSignedPayload(cm map[string]any) map[string]any {
	if p, ok := cm["payload"].(map[string]any); ok {
		return p
	}
	return map[string]any{}
}

var chainClaimTypeNames = map[string]string{
	"CLAIM_TYPE_TOKEN_GENERATED":     "TOKEN_GENERATED",
	"CLAIM_TYPE_PII_SANITIZED":       "PII_SANITIZED",
	"CLAIM_TYPE_INFERENCE_COMPLETED": "INFERENCE_COMPLETED",
	"CLAIM_TYPE_EVENTS_RECORDED":     "EVENTS_RECORDED",
}

func chainVerifySig(pub ed25519.PublicKey, msg, sig []byte) bool {
	return len(pub) == ed25519.PublicKeySize && len(sig) == ed25519.SignatureSize && ed25519.Verify(pub, msg, sig)
}

func chainVerifyCanonical(pub ed25519.PublicKey, m map[string]any, sig []byte) bool {
	b, err := CanonicalLexeme(m)
	return err == nil && chainVerifySig(pub, b, sig)
}

// RunChain implements README § Verification recipe. Certificate problems are
// a FAILED result, never an error.
func RunChain(certJSON []byte, keys ChainKeys, minV3 bool) ChainResult {
	// 1. Shape.
	root, err := DecodeDocument(certJSON)
	if err != nil {
		return chainDecide("1", chainNo)
	}
	cert, ok := root.(map[string]any)
	if !ok {
		return chainDecide("1", chainNo)
	}
	certID, ok1 := cert["certificate_id"].(string)
	reqID, ok2 := cert["request_id"].(string)
	wkid, ok3 := cert["witness_key_id"].(string)
	issuedAt, ok4 := cert["issued_at"].(string)
	claimsRaw, ok5 := cert["claims"].([]any)
	ver, ok6 := cert["verification"].(map[string]any)
	pv, ok7 := ChainInteger(cert["protocol_version"], math.MaxUint32)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 || !ok6 || !ok7 || len(claimsRaw) == 0 {
		return chainDecide("1", chainNo)
	}
	sealed, ok := ver["overall_verdict"].(string)
	if !ok {
		return chainDecide("1", chainNo)
	}
	unsignedTier, okT := chainOptString(ver["cert_tier"])
	byok, okB := ver["byok_exempt"].(bool)
	if ver["byok_exempt"] == nil {
		okB = true
	}
	var emitted uint64
	okE := true
	if cert["signable_protocol_version_emitted"] != nil {
		emitted, okE = ChainInteger(cert["signable_protocol_version_emitted"], math.MaxInt32)
	}
	v3sig, okV3 := chainOptString(cert["signable_v3_signature"])
	_, okW := chainOptString(cert["witness_signature"])
	_, okC := chainOptString(cert["client_id"])
	_, okA := chainOptString(cert["api_key_id"])
	if !okT || !okB || !okE || !okV3 || !okW || !okC || !okA {
		return chainDecide("1", chainNo)
	}
	claims := make([]map[string]any, len(claimsRaw))
	claimIDs := make([]any, len(claimsRaw))
	for i, c := range claimsRaw {
		m, ok := c.(map[string]any)
		if !ok {
			return chainDecide("1", chainNo)
		}
		id, okID := m["claim_id"].(string)
		_, okSvc := m["service_id"].(string)
		if !okID || !okSvc {
			return chainDecide("1", chainNo)
		}
		claims[i] = m
		claimIDs[i] = id
	}
	// 2. Protocol version.
	if pv != 2 {
		return chainDecide("2", chainNo)
	}
	// 3. Witness identity.
	if wkid != keys.WitnessKeyID {
		return chainDecide("3", chainNo)
	}
	// 4. Signable-version tri-state.
	v3present := strings.TrimSpace(v3sig) != ""
	if (emitted >= 3) != v3present {
		return chainDecide("4", chainNo)
	}
	// 5a. issued_at.
	issuedUTC, ok := ChainIssuedAt(issuedAt)
	if !ok {
		return chainDecide("5a", chainNo)
	}
	// 5b. v2 witness signature.
	v2 := map[string]any{
		"certificate_id": certID, "request_id": reqID, "protocol_version": json.Number("2"),
		"claim_ids": claimIDs, "issued_at": issuedUTC,
		"overall_verdict": strings.TrimPrefix(sealed, "VERDICT_"), "witness_key_id": wkid,
	}
	wsig, ok := chainB64(cert["witness_signature"])
	if !ok || len(wsig) == 0 || !chainVerifyCanonical(keys.Witness, v2, wsig) {
		return chainDecide("5b", chainNo)
	}
	// 5c. v3 witness signature.
	sv := "v2"
	if v3present {
		v3 := map[string]any{}
		for k, v := range v2 {
			v3[k] = v
		}
		v3["client_id"] = cert["client_id"]
		v3["api_key_id"] = cert["api_key_id"]
		v3["byok_exempt"] = byok
		v3["redaction_manifest_hash"] = chainSanitizerHash(claims, "redaction_manifest_hash")
		v3["sanitized_fields_body_hash"] = chainSanitizerHash(claims, "sanitized_fields_hash")
		v3["tms_manifest_hash"] = chainSanitizerHash(claims, "tms_manifest_hash")
		sig, ok := chainB64(v3sig)
		if !ok || !chainVerifyCanonical(keys.Witness, v3, sig) {
			return chainDecide("5c", chainNo)
		}
		sv = "v3"
	}
	// 5d. Policy.
	if minV3 && sv != "v3" {
		return chainDecide("5d", chainNo)
	}
	// 6. Sealed verdict + claim-id uniqueness.
	if sealed == "VERDICT_FAILED" {
		return chainDecide("6a", chainNo)
	}
	if sealed != "VERDICT_VERIFIED" && sealed != "VERDICT_PARTIAL" {
		return chainDecide("6b", chainNo)
	}
	listed := map[string]bool{}
	for _, id := range claimIDs {
		if listed[id.(string)] {
			return chainDecide("6c", chainNo)
		}
		listed[id.(string)] = true
	}
	// 7. Every claim, in array order.
	canon := make([]map[string]any, len(claims))
	typedUnauth := []string{}
	for i, c := range claims {
		svc := c["service_id"].(string)
		// 7a.
		pub, ok := keys.Services[svc]
		if !ok {
			return chainDecide("7a", chainNo)
		}
		// 7b.
		cp, ok1 := chainB64(c["canonical_payload"])
		sig, ok2 := chainB64(c["signature"])
		if !ok1 || !ok2 {
			return chainDecide("7b", chainNo)
		}
		// 7c / 7d.
		own := chainVerifySig(pub, cp, sig)
		if !own {
			for other, k := range keys.Services {
				if other != svc && chainVerifySig(k, cp, sig) {
					return chainDecide("7c", chainNo)
				}
			}
			return chainDecide("7d", chainNo)
		}
		// 7e.
		parsed, err := DecodeDocument(cp)
		cm, isObj := parsed.(map[string]any)
		if err != nil || !isObj {
			return chainDecide("7e", chainNo)
		}
		// 7f.
		signedID, isStr := cm["claim_id"].(string)
		if !isStr || !listed[signedID] {
			return chainDecide("7f", chainNo)
		}
		// 7g.
		ds, ok1 := chainStrList(c["data_seen"])
		dns, ok2 := chainStrList(c["data_not_seen"])
		outerReq, ok3 := chainOptString(c["request_id"])
		ct, _ := c["claim_type"].(string)
		if !ok1 || !ok2 || !ok3 {
			return chainDecide("7g", chainNo)
		}
		rebuilt, err := CanonicalLexeme(map[string]any{
			"claim_id": c["claim_id"], "request_id": outerReq, "service_id": svc,
			"claim_type": chainClaimTypeNames[ct], "data_seen": ds, "data_not_seen": dns,
			"payload": cm["payload"], "timestamp": cm["timestamp"],
		})
		if err != nil || !bytes.Equal(rebuilt, cp) {
			return chainDecide("7g", chainNo)
		}
		// 7h.
		if cm["request_id"] != reqID {
			return chainDecide("7h", chainNo)
		}
		// 7i.
		p := chainSignedPayload(cm)
		if !chainTypedBound(c, chainClaimTypeNames[ct], p) {
			return chainDecide("7i", chainNo)
		}
		typedUnauth = append(typedUnauth, chainTypedUnbound(i, c, p)...)
		canon[i] = p
	}
	// 8a. Signed digest lists.
	digestClaim := -1
	var digests []string
	for i, c := range claims {
		if c["service_id"] != "dsa-ai" || c["claim_type"] != "CLAIM_TYPE_INFERENCE_COMPLETED" {
			continue
		}
		raw, has := canon[i]["upstream_body_sha256"]
		if !has {
			continue
		}
		d, ok := chainStrList(raw)
		if !ok || raw == nil || len(d) == 0 || digestClaim >= 0 {
			return chainDecide("8a", chainNo)
		}
		for _, x := range d {
			if !chainLowerHex64.MatchString(x) {
				return chainDecide("8a", chainNo)
			}
		}
		digestClaim, digests = i, d
	}
	// 8b. Stored bodies only on the digest-carrying claim.
	bodiesOf := func(c map[string]any) ([]any, bool) {
		inf, isObj := c["inference"].(map[string]any)
		if !isObj || inf["upstream_request_bodies"] == nil {
			return nil, true
		}
		b, ok := inf["upstream_request_bodies"].([]any)
		return b, ok
	}
	for i, c := range claims {
		b, ok := bodiesOf(c)
		if !ok || (len(b) > 0 && i != digestClaim) {
			return chainDecide("8b", chainNo)
		}
	}
	// 8c. Stored bodies hash to the signed digests.
	if digestClaim >= 0 {
		bodies, _ := bodiesOf(claims[digestClaim])
		if len(bodies) > 0 {
			if len(bodies) != len(digests) {
				return chainDecide("8c", chainNo)
			}
			for j, b := range bodies {
				raw, ok := chainB64(b)
				sum := sha256.Sum256(raw)
				if !ok || hex.EncodeToString(sum[:]) != digests[j] {
					return chainDecide("8c", chainNo)
				}
			}
		}
	}
	// 8d. cert_tier against the signed copies.
	signedTier, tierOK, tierCap := chainCertTier(claims, canon, unsignedTier, sealed)
	if !tierOK {
		return chainDecide("8d", chainNo)
	}
	// 9. Ceilings.
	egress := "unattested"
	if digestClaim >= 0 {
		egress = "signed_digests"
	}
	userUnredacted := "false"
	for i, c := range claims {
		if svc := c["service_id"]; svc != "dsa-sanitizer" && svc != "dsa-sanitizer-streaming" {
			continue
		}
		if layers, ok := canon[i]["layers_active"].([]any); ok {
			for _, l := range layers {
				if l == chainUserUnredactedTok {
					userUnredacted = "true"
				}
			}
		}
	}
	st := chainPass{egress: egress, sv: sv, userUnredacted: userUnredacted, tier: signedTier, typedUnauth: typedUnauth}
	for i := range claims {
		// Key PRESENCE: a signed null counts.
		if _, has := canon[i]["inference_outcome"]; has {
			return chainDecide("9a", st)
		}
	}
	if userUnredacted == "true" {
		return chainDecide("9b", st)
	}
	if sealed == "VERDICT_PARTIAL" {
		return chainDecide("9c", st)
	}
	if egress == "unattested" || tierCap {
		return chainDecide("9d", st)
	}
	return chainDecide("9e", st)
}

// chainCertTier — README step 8d. Returns the signed tier, whether the
// unsigned label passes, and whether the result is capped at
// EGRESS_UNATTESTED (fix A).
func chainCertTier(claims []map[string]any, canon []map[string]any, unsigned, sealed string) (string, bool, bool) {
	carriers := map[string][]any{}
	n := 0
	for i, c := range claims {
		if t, has := canon[i]["cert_tier"]; has {
			svc := c["service_id"].(string)
			carriers[svc] = append(carriers[svc], t)
			n++
		}
	}
	signed := "inconsistent"
	switch {
	case n == 0:
		signed = "absent"
	case n == 2 && len(carriers["dsa-gateway"]) == 1 && len(carriers["dsa-ai"]) == 1 &&
		carriers["dsa-gateway"][0] == "input-shield" && carriers["dsa-ai"][0] == "input-shield":
		signed = "input_shield"
	}
	if unsigned != "" && unsigned != "full_chain" && unsigned != "input_shield" {
		return signed, false, false
	}
	if (signed == "absent" && (unsigned == "" || unsigned == "full_chain")) ||
		(signed == "input_shield" && unsigned == "input_shield") {
		return signed, true, false
	}
	if signed == "input_shield" && unsigned == "" {
		return signed, true, true
	}
	return signed, sealed == "VERDICT_PARTIAL", false
}

// chainConditionalTyped — step 7i rows that bind a typed field only while its
// signed key carries the compared JSON type.
var chainConditionalTyped = []struct{ kind, field, signedType string }{
	{"inference", "isolation_probe", "string"},
	{"inference", "model_used", "string"},
	{"sanitizer", "pii_entities_found", "number"},
	{"bridge", "token_hash", "string"},
	{"bridge", "encryption_enabled", "boolean"},
	{"audit", "chain_head_hash", "string"},
	{"audit", "chain_length", "number"},
}

func chainTypedUnbound(i int, c map[string]any, p map[string]any) []string {
	var out []string
	for _, r := range chainConditionalTyped {
		if _, isObj := c[r.kind].(map[string]any); !isObj {
			continue
		}
		var bound bool
		switch p[r.field].(type) {
		case string:
			bound = r.signedType == "string"
		case json.Number:
			bound = r.signedType == "number"
		case bool:
			bound = r.signedType == "boolean"
		}
		if !bound {
			out = append(out, fmt.Sprintf("claims[%d].%s.%s", i, r.kind, r.field))
		}
	}
	return out
}

// chainSanitizerHash: the FIRST dsa-sanitizer claim's canonical
// payload.payload[key] as a non-empty string, else nil (witness
// sanitizerPayloadString).
func chainSanitizerHash(claims []map[string]any, key string) any {
	for _, c := range claims {
		if c["service_id"] != "dsa-sanitizer" {
			continue
		}
		cp, ok := chainB64(c["canonical_payload"])
		if !ok || len(cp) == 0 {
			return nil
		}
		parsed, err := DecodeDocument(cp) // the same strict parser as every other read
		outer, isObj := parsed.(map[string]any)
		if err != nil || !isObj {
			return nil
		}
		inner, ok := outer["payload"].(map[string]any)
		if !ok {
			inner = outer
		}
		if s, ok := inner[key].(string); ok && s != "" {
			return s
		}
		return nil
	}
	return nil
}

var chainTypedKinds = map[string]struct {
	key      string
	requires []string
}{
	"TOKEN_GENERATED":     {"bridge", []string{"token_hash", "encryption_enabled"}},
	"PII_SANITIZED":       {"sanitizer", []string{"pii_entities_found", "layers_active", "qi_score"}},
	"INFERENCE_COMPLETED": {"inference", []string{"response_hash", "isolation_probe", "model_used", "inference_outcome"}},
	"EVENTS_RECORDED":     {"audit", []string{"chain_head_hash", "chain_length"}},
}

var chainProbeEnum = map[string]string{
	"VERIFIED": "ISOLATION_PROBE_VERIFIED", "BREACHED": "ISOLATION_PROBE_BREACHED",
	"LOCKED": "ISOLATION_PROBE_LOCKED", "BYOK_EXEMPT": "ISOLATION_PROBE_BYOK_EXEMPT",
}

// chainASCIIUpper upper-cases a-z only (the TS and Python SDKs do the same;
// Unicode case mapping differs between the three languages).
func chainASCIIUpper(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}, s)
}

func chainQiVerdict(s string) string {
	switch chainASCIIUpper(strings.Trim(s, " \t\n\r\f\v")) {
	case "PASS":
		return "QI_VERDICT_PASS"
	case "GENERALIZED":
		return "QI_VERDICT_GENERALIZED"
	case "BLOCKED":
		return "QI_VERDICT_BLOCKED"
	}
	return "QI_VERDICT_UNKNOWN"
}

func chainSameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// chainTypedBound — README step 7i.
func chainTypedBound(c map[string]any, claimType string, p map[string]any) bool {
	present := ""
	for _, k := range []string{"bridge", "sanitizer", "inference", "audit"} {
		if c[k] == nil {
			continue
		}
		if _, isObj := c[k].(map[string]any); !isObj || present != "" {
			return false
		}
		present = k
	}
	kind, named := chainTypedKinds[claimType]
	if present != "" && (!named || present != kind.key) {
		return false
	}
	if named && present == "" {
		for _, k := range kind.requires {
			if _, has := p[k]; has {
				return false
			}
		}
	}
	signedLayers, _ := p["layers_active"].([]any)
	for _, l := range signedLayers {
		if l == chainUserUnredactedTok && present != "sanitizer" {
			return false
		}
	}
	if present == "" {
		return true
	}
	t := c[present].(map[string]any)
	switch present {
	case "inference":
		probe, ok := chainOptString(t["isolation_probe"])
		if !ok {
			return false
		}
		if probe == "" {
			probe = "ISOLATION_PROBE_UNKNOWN"
		}
		if s, isStr := p["isolation_probe"].(string); isStr {
			want, known := chainProbeEnum[s]
			if !known {
				want = "ISOLATION_PROBE_UNKNOWN"
			}
			if probe != want {
				return false
			}
		} else if probe == "ISOLATION_PROBE_VERIFIED" || probe == "ISOLATION_PROBE_BYOK_EXEMPT" {
			return false
		}
		model, ok := chainOptString(t["model_used"])
		if !ok {
			return false
		}
		if s, isStr := p["model_used"].(string); isStr && model != s {
			return false
		}
		rh, ok := chainB64(t["response_hash"])
		if !ok {
			return false
		}
		srh, isStr := p["response_hash"].(string)
		if (len(rh) > 0) != isStr || (len(rh) > 0 && hex.EncodeToString(rh) != srh) {
			return false
		}
	case "sanitizer":
		if raw, has := p["pii_entities_found"]; has {
			if _, isNum := raw.(json.Number); isNum {
				want, ok := ChainInteger(raw, math.MaxUint32)
				got, okT := chainTypedUint(t["pii_entities_found"])
				if !ok || !okT || want != got {
					return false
				}
			}
		}
		typedLayers, ok := chainStrList(t["layers_active"])
		if !ok {
			return false
		}
		signedList, ok := chainStrList(p["layers_active"])
		if !ok || !chainSameStrings(typedLayers, signedList) {
			return false
		}
		if !chainQiBound(p["qi_score"], t["qi_score"]) {
			return false
		}
	case "bridge":
		if s, isBool := p["encryption_enabled"].(bool); isBool {
			got, _ := t["encryption_enabled"].(bool)
			if t["encryption_enabled"] != nil {
				if _, isBoolT := t["encryption_enabled"].(bool); !isBoolT {
					return false
				}
			}
			if got != s {
				return false
			}
		}
		if s, isStr := p["token_hash"].(string); isStr {
			th, ok := chainB64(t["token_hash"])
			if !ok || hex.EncodeToString(th) != s {
				return false
			}
		}
	case "audit":
		if s, isStr := p["chain_head_hash"].(string); isStr {
			h, ok := chainB64(t["chain_head_hash"])
			if !ok || hex.EncodeToString(h) != s {
				return false
			}
		}
		if raw, has := p["chain_length"]; has {
			if _, isNum := raw.(json.Number); isNum {
				want, ok := ChainInteger(raw, math.MaxUint64)
				got, okT := chainTypedUint(t["chain_length"])
				if !ok || !okT || want != got {
					return false
				}
			}
		}
	}
	return true
}

// chainQiBound — the qi_score part of step 7i.
func chainQiBound(signedRaw, typedRaw any) bool {
	s, signedObj := signedRaw.(map[string]any)
	if !signedObj {
		return typedRaw == nil
	}
	t, typedObj := typedRaw.(map[string]any)
	if !typedObj {
		return false
	}
	ka, ok := ChainInteger(s["k_anonymity"], math.MaxUint32)
	tka, okT := chainTypedUint(t["k_anonymity"])
	if !ok || !okT || ka != tka {
		return false
	}
	for _, k := range []string{"l_diversity", "risk_score", "threshold"} {
		sf, ok := ChainFloat32(s[k], false)
		tf, okT := ChainFloat32(t[k], true)
		if !ok || !okT || sf != tf {
			return false
		}
	}
	sv, ok := s["verdict"].(string)
	tv, okT := chainOptString(t["verdict"])
	if tv == "" {
		tv = "QI_VERDICT_UNKNOWN"
	}
	if !ok || !okT || chainQiVerdict(sv) != tv {
		return false
	}
	sfg, ok := s["fields_generalized"].([]any)
	if !ok {
		return false
	}
	sfgs, ok := chainStrList(sfg)
	tfg, okT := chainStrList(t["fields_generalized"])
	return ok && okT && chainSameStrings(sfgs, tfg)
}
