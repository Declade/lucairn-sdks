package verify

import (
	"encoding/base64"
	"encoding/json"
)

// DeriveV3SignedBytesInput carries the 13-key v3 signable map inputs sourced
// from the certificate and the sanitizer claim's canonical_payload.
//
// Sourcing discipline (BLOCKER-1, PR #247 assembler.go:337-378):
//
//   - RedactionManifestHash, SanitizedFieldsBodyHash, TMSManifestHash: read
//     from the dsa-sanitizer claim's canonical_payload["payload"] JSON, NOT
//     from the stripped proto body fields. The gateway server-side strip
//     pipeline nil-fills SanitizerClaim.RedactionManifestBody +
//     SanitizedFieldsBody BEFORE marshalling to the SDK; the hashes survive
//     intact in canonical_payload because it is sanitizer-signed and travels
//     through the gateway unchanged.
//
//   - ClientID, APIKeyID: optional strings from the certificate top-level
//     (proto fields 14, 15). nil → canonical_json emits null. Non-nil →
//     the string value.
//
//   - ByokExempt: bool from cert.verification.byok_exempt. Default false on
//     older certs that omit the field.
//
// protocol_version in the v3 map is still 2 (NOT 3). The cert-shape
// protocol_version is 2; the SDK-signable-version is signalled separately via
// cert.signable_protocol_version_emitted. A future maintainer who "fixes" this
// literal to 3 will break byte-identity for every v3-SDK install in the field.
// Source: assembler.go:383-388 comment.
type DeriveV3SignedBytesInput struct {
	// v2 fields (shared) — same constraints as DeriveSignedBytesInput.
	CertificateID          string
	RequestID              string
	ClaimRequestIDs        []string
	ClaimIDs               []string
	IssuedAt               string
	OverallVerdictFullName string
	WitnessKeyID           string

	// v3 promoted carry-forwards.
	ClientID   *string // nil → null in signable
	APIKeyID   *string // nil → null in signable
	ByokExempt bool

	// Hash fields from sanitizer canonical_payload["payload"] — nil if absent.
	RedactionManifestHash   *string // key: "redaction_manifest_hash"
	SanitizedFieldsBodyHash *string // key: "sanitized_fields_hash"
	TMSManifestHash         *string // key: "tms_manifest_hash" (nil pre-Slice-5)
}

// DeriveV3SignedBytes builds the exact byte sequence the witness signs for a
// v3 (13-key) signable map.
//
// v3 = v2's 7 keys + 6 additional:
//
//	client_id, api_key_id, byok_exempt,
//	redaction_manifest_hash, sanitized_fields_body_hash, tms_manifest_hash
//
// v2 byte-identity is maintained independently (DeriveSignedBytes).
// v3 reconstruction mirrors assembler.go:380-413 field-for-field.
//
// issued_at is normalized via RFC3339Nano parse+reformat (H6 fix — same
// normalizeIssuedAt call as DeriveSignedBytes).
func DeriveV3SignedBytes(in DeriveV3SignedBytesInput) ([]byte, error) {
	if len(in.ClaimRequestIDs) == 0 || len(in.ClaimIDs) == 0 {
		return nil, &MalformedError{
			Reason: "cert.claims is empty — certificate must contain at least one claim",
		}
	}
	if len(in.ClaimRequestIDs) != len(in.ClaimIDs) {
		return nil, &MalformedError{
			Reason: "cert.claims length mismatch between request_ids and claim_ids — SDK bug",
		}
	}
	if in.ClaimRequestIDs[0] != in.RequestID {
		return nil, &MalformedError{
			Reason: "cert.request_id does not match cert.claims[0].request_id (gateway invariant violated)",
		}
	}
	goShortForm, ok := verdictFullToShort[in.OverallVerdictFullName]
	if !ok {
		return nil, &MalformedError{
			Reason: "unknown verification.overall_verdict literal: " + in.OverallVerdictFullName +
				" — SDK may be out of date",
		}
	}

	claimIDsAny := make([]any, len(in.ClaimIDs))
	for i, id := range in.ClaimIDs {
		claimIDsAny[i] = id
	}

	// optStr converts *string to the canonical-JSON-friendly value:
	// nil → nil (canonical_json emits null) ; non-nil → string value.
	// Mirrors assembler.go:455-465 optionalStringForSignable.
	optStr := func(p *string) any {
		if p == nil {
			return nil
		}
		return *p
	}

	v3 := map[string]any{
		// --- 7 v2 keys (same encoding) ---
		"certificate_id":   in.CertificateID,
		"request_id":       in.RequestID,
		"protocol_version": SignableProtocolVersion, // literal 2, NOT signable_protocol_version_emitted
		"claim_ids":        claimIDsAny,
		"issued_at":        normalizeIssuedAt(in.IssuedAt),
		"overall_verdict":  goShortForm,
		"witness_key_id":   in.WitnessKeyID,
		// --- v3-only promoted carry-forwards ---
		"client_id":                  optStr(in.ClientID),
		"api_key_id":                 optStr(in.APIKeyID),
		"byok_exempt":                in.ByokExempt,
		"redaction_manifest_hash":    optStr(in.RedactionManifestHash),
		"sanitized_fields_body_hash": optStr(in.SanitizedFieldsBodyHash),
		"tms_manifest_hash":          optStr(in.TMSManifestHash),
	}
	return CanonicalJSON(v3)
}

// ExtractSanitizerPayloadHash scans the raw cert claims array for the
// dsa-sanitizer claim, decodes its canonical_payload (base64 JSON), and
// returns the string at canonical_payload["payload"][key], or nil if absent.
//
// This is the SDK-side mirror of assembler.go:467-511
// sanitizerCanonicalPayloadStringForSignable. The strip-surviving discipline
// (BLOCKER-1) requires reading from canonical_payload, not from the proto body
// fields (which are nil-filled by the gateway server-side strip pipeline).
//
// rawClaims is the raw cert JSON map's "claims" array ([]any of map[string]any).
func ExtractSanitizerPayloadHash(rawClaims []any, key string) *string {
	for _, c := range rawClaims {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if cm["service_id"] != "dsa-sanitizer" {
			continue
		}
		cpB64, ok := cm["canonical_payload"].(string)
		if !ok || cpB64 == "" {
			return nil
		}
		cpBytes, err := base64.StdEncoding.DecodeString(cpB64)
		if err != nil {
			return nil
		}
		var outer map[string]any
		if err := json.Unmarshal(cpBytes, &outer); err != nil {
			return nil
		}
		inner, ok := outer["payload"].(map[string]any)
		if !ok {
			// Fallback: some older canonical_payload shapes have the keys at the
			// top level. Mirror assembler.go:500-503.
			inner = outer
		}
		v, ok := inner[key].(string)
		if !ok || v == "" {
			return nil
		}
		return &v
	}
	return nil
}
