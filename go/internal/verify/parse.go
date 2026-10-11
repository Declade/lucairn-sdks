package verify

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"
)

// ErrParseMalformed is returned by Parse on structural validation failure
// that should surface as CertificateError with ReasonMalformed. The Reason
// field is the human-facing reason string.
type ErrParseMalformed struct {
	Reason        string
	CertificateID string
}

func (e *ErrParseMalformed) Error() string { return e.Reason }

// Parse runs structural validation on a raw JSON certificate body. It
// returns a typed rawCertificate for downstream signable derivation, or
// an *ErrParseMalformed that the caller wraps as CertificateError.
//
// Does NOT validate enum literal membership beyond "string" — that check
// belongs in signable derivation (where the verdict-to-short-form map is).
type RawCert struct {
	CertificateID    string
	RequestID        string
	ProtocolVersion  int
	ClaimIDs         []string
	ClaimRequestIDs  []string
	IssuedAt         string
	OverallVerdict   string
	WitnessKeyID     string
	WitnessSignature string

	// v3 dual-protocol fields (optional — absent on v2 certs).
	// SignableProtocolVersionEmitted = 0 means the field was absent (v2 cert).
	// = 3 means the cert carries both v2 + v3 signatures.
	SignableProtocolVersionEmitted int
	// SignableV3Signature is the base64-encoded Ed25519 signature over the
	// 13-key v3 signable map. Empty string when absent.
	SignableV3Signature string

	// Raw claims array ([]any) for v3 sanitizer-payload hash extraction.
	// Populated by Parse so the pipeline can call ExtractSanitizerPayloadHash
	// without re-parsing the cert.
	RawClaims []any

	// v3 promoted carry-forward fields from cert top-level.
	ClientID   *string // cert.client_id   (optional proto field 14)
	APIKeyID   *string // cert.api_key_id   (optional proto field 15)
	ByokExempt bool    // cert.verification.byok_exempt
}

func Parse(raw any) (*RawCert, error) {
	m, ok := raw.(map[string]any)
	if !ok {
		return nil, &ErrParseMalformed{Reason: "certificate is not a JSON object"}
	}

	var certID string
	if s, ok := m["certificate_id"].(string); ok {
		certID = s
	}

	mustStr := func(key string) (string, bool) {
		s, ok := m[key].(string)
		return s, ok
	}

	cert := &RawCert{}
	var ok2 bool
	if cert.CertificateID, ok2 = mustStr("certificate_id"); !ok2 || cert.CertificateID == "" {
		return nil, &ErrParseMalformed{Reason: "certificate missing required field certificate_id", CertificateID: certID}
	}
	if cert.RequestID, ok2 = mustStr("request_id"); !ok2 {
		return nil, &ErrParseMalformed{Reason: "certificate missing required field request_id", CertificateID: certID}
	}
	if cert.WitnessKeyID, ok2 = mustStr("witness_key_id"); !ok2 {
		return nil, &ErrParseMalformed{Reason: "certificate missing required field witness_key_id", CertificateID: certID}
	}
	if cert.WitnessSignature, ok2 = mustStr("witness_signature"); !ok2 {
		return nil, &ErrParseMalformed{Reason: "certificate missing required field witness_signature", CertificateID: certID}
	}
	if cert.IssuedAt, ok2 = mustStr("issued_at"); !ok2 {
		return nil, &ErrParseMalformed{Reason: "certificate missing required field issued_at", CertificateID: certID}
	}

	// protocol_version: required; the shared value rule (versionValue).
	pv, pvOK := versionValue(m["protocol_version"])
	if !pvOK {
		return nil, &ErrParseMalformed{Reason: "protocol_version must be an integer", CertificateID: certID}
	}
	cert.ProtocolVersion = pv

	claimsRaw, ok2 := m["claims"].([]any)
	if !ok2 {
		return nil, &ErrParseMalformed{Reason: "certificate missing required field claims", CertificateID: certID}
	}
	cert.ClaimIDs = make([]string, 0, len(claimsRaw))
	cert.ClaimRequestIDs = make([]string, 0, len(claimsRaw))
	for i, cRaw := range claimsRaw {
		cm, ok3 := cRaw.(map[string]any)
		if !ok3 {
			return nil, &ErrParseMalformed{
				Reason:        "claims[" + itoa(i) + "] is not a JSON object",
				CertificateID: certID,
			}
		}
		cid, ok3 := cm["claim_id"].(string)
		if !ok3 {
			return nil, &ErrParseMalformed{
				Reason:        "claims[" + itoa(i) + "].claim_id must be a string",
				CertificateID: certID,
			}
		}
		crid, ok3 := cm["request_id"].(string)
		if !ok3 {
			return nil, &ErrParseMalformed{
				Reason:        "claims[" + itoa(i) + "].request_id must be a string",
				CertificateID: certID,
			}
		}
		cert.ClaimIDs = append(cert.ClaimIDs, cid)
		cert.ClaimRequestIDs = append(cert.ClaimRequestIDs, crid)
	}

	verification, ok2 := m["verification"].(map[string]any)
	if !ok2 {
		return nil, &ErrParseMalformed{Reason: "certificate missing required field verification", CertificateID: certID}
	}
	ov, ok2 := verification["overall_verdict"].(string)
	if !ok2 {
		return nil, &ErrParseMalformed{
			Reason:        "verification.overall_verdict must be a string enum literal",
			CertificateID: certID,
		}
	}
	cert.OverallVerdict = ov

	// byok_exempt (optional bool, default false for older certs that omit it).
	if be, ok3 := verification["byok_exempt"].(bool); ok3 {
		cert.ByokExempt = be
	}

	// v3 dual-protocol fields (optional — absent on legacy v2 certs).
	// signable_protocol_version_emitted: absent or JSON null → 0 (v2 cert;
	// zero value). Present and not null: the shared value rule, otherwise
	// malformed.
	if pve := m["signable_protocol_version_emitted"]; pve != nil {
		n, ok3 := versionValue(pve)
		if !ok3 {
			return nil, &ErrParseMalformed{Reason: "signable_protocol_version_emitted must be a non-negative integer", CertificateID: certID}
		}
		cert.SignableProtocolVersionEmitted = n
	}
	if sv3, ok3 := mustStr("signable_v3_signature"); ok3 {
		cert.SignableV3Signature = sv3
	}

	// Store raw claims for v3 sanitizer-payload hash extraction.
	cert.RawClaims = claimsRaw

	// v3 promoted carry-forward fields.
	//
	// Presence-preserving decode: a JSON string value (including "") means the
	// field is present → set the pointer to that string. Only an absent key or
	// an explicit JSON null (which decodes as a nil interface value) maps to a
	// nil pointer. Mirrors assembler.go::optionalStringForSignable where
	// nil → canonical-JSON null and "" → canonical-JSON "".
	//
	// The previous `ok3 && s != ""` guard incorrectly collapsed present empty
	// strings to nil, producing a canonical-JSON null in the v3 signable map
	// instead of "" — a byte-identity divergence from the assembler.
	if raw, exists := m["client_id"]; exists {
		if s, ok3 := raw.(string); ok3 {
			cert.ClientID = &s
		}
		// nil raw (explicit JSON null) → cert.ClientID stays nil → canonical null ✓
	}
	if raw, exists := m["api_key_id"]; exists {
		if s, ok3 := raw.(string); ok3 {
			cert.APIKeyID = &s
		}
		// nil raw (explicit JSON null) → cert.APIKeyID stays nil → canonical null ✓
	}

	return cert, nil
}

// AnchorStatus extracts cert.anchor_status.status as a string, or empty
// string if not present. Used by the pipeline to surface anchor_status in
// the result without re-parsing the entire cert.
func AnchorStatus(raw any) string {
	m, ok := raw.(map[string]any)
	if !ok {
		return ""
	}
	as, ok := m["anchor_status"].(map[string]any)
	if !ok {
		return ""
	}
	s, _ := as["status"].(string)
	return s
}

// tiny int-to-string helper (avoid importing strconv here to keep parse.go
// dependency-free; Go's standard strconv is fine — this is just to keep
// the call-site shape simple).
func itoa(i int) string {
	// Tiny; numbers we handle are always small claim indices.
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	var buf [16]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// sentinel for errors.Is consumers
var ErrNotMap = errors.New("not a JSON object")

// versionValue applies the value rule of the two version fields
// (protocol_version, signable_protocol_version_emitted), the same in the
// TypeScript, Python and Go SDKs: a JSON number whose value is an integer
// >= 0 and at most 2^64 − 1. It returns the value as an int that is safe on
// every architecture: the decision is taken on the float64 (or on the digits
// of a json.Number) and a float64 is never converted to int unless it is in
// range — converting an out-of-range float64 to int gives a different result
// on arm64 and amd64. Values above math.MaxInt32 are reported as
// math.MaxInt32: callers only compare against 2 and 3.
//
// Accepted Go types: float64 (what encoding/json produces; a float64 cannot
// hold 2^64 − 1, so the upper bound is "below 2^64"), int, and json.Number
// (digits only, at most 20, value at most 2^64 − 1). Everything else —
// strings, booleans, arrays, objects, fractions, negatives, NaN, ±Inf — is
// refused.
func versionValue(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		// 18446744073709551616 = 2^64, exactly representable.
		if math.IsNaN(n) || n < 0 || n >= 18446744073709551616.0 || n != math.Trunc(n) {
			return 0, false
		}
		if n > math.MaxInt32 {
			return math.MaxInt32, true
		}
		return int(n), true
	case int:
		if n < 0 {
			return 0, false
		}
		if n > math.MaxInt32 {
			return math.MaxInt32, true
		}
		return n, true
	case json.Number:
		s := string(n)
		if len(s) == 0 || len(s) > 20 {
			return 0, false
		}
		for i := 0; i < len(s); i++ {
			if s[i] < '0' || s[i] > '9' {
				return 0, false
			}
		}
		u, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, false
		}
		if u > math.MaxInt32 {
			return math.MaxInt32, true
		}
		return int(u), true
	default:
		return 0, false
	}
}
