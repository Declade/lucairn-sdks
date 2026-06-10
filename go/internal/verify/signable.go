package verify

import "time"

// Derive the exact byte sequence the witness signs.
//
// Port of
//   dual-sandbox-architecture/services/veil-witness/internal/assembler/assembler.go:117-132
//
// CRITICAL ENCODING NOTE (resolved 2026-04-20 after contract-drift-detector
// caught it in the TS port):
//
// The Go assembler signs vr.OverallVerdict (verifier.go:56 — type string)
// DIRECTLY. vr.OverallVerdict holds short-form strings like "VERIFIED",
// NOT the proto enum integer and NOT the full-name protojson form
// "VERDICT_VERIFIED". The signable emits a JSON string (quoted) via
// canonical JSON's default string path — NOT an integer.
//
// Protojson → Go short-form mapping: the gateway emits full-name
// VERDICT_* literals on the wire (UseProtoNames + default enum
// serialization); the witness signs the short-form. The SDK must convert.
//
// ISSUED_AT NORMALIZATION (H6 — ~10% verify-failure root cause):
//
// The witness assembler signs issued_at with time.RFC3339Nano which strips
// trailing zeros from fractional seconds:
//   "2026-06-10T00:01:59.878143387Z"     ← what witness signs
// The gateway protojson marshaller emits zero-padded nanoseconds:
//   "2026-06-10T00:01:59.878143387000000000Z" ← what protojson may produce
//
// The SDK feeds the served string directly into the signable bytes, causing
// a mismatch on any cert where the nanoseconds aren't already in RFC3339Nano
// canonical form. Fix: normalize via parse-then-reformat before placing
// issued_at in signable bytes, in BOTH v2 and v3 paths.
//
// normalizeIssuedAt parses the served string with RFC3339Nano (which handles
// any number of fractional-second digits) and re-emits with RFC3339Nano
// (which strips trailing zeros). If parsing fails the original string is
// returned unchanged (fail-open: verification will fail downstream if the
// byte mismatch was real, but we don't swallow a legit parse on a
// well-formed timestamp just because nanoseconds happen to round-trip
// cleanly).

// SignableProtocolVersion is the wire protocol the signable subset is
// built against. Mirrors pipeline.SupportedProtocolVersion; these two
// constants must update in lockstep. Lifting the literal out prevents
// a future contributor from bumping one without the other.
const SignableProtocolVersion = 2

// verdictFullToShort maps the protojson full-name verdict to the Go
// assembler's short-form. Unknown values are rejected upstream as
// malformed.
var verdictFullToShort = map[string]string{
	"VERDICT_UNSPECIFIED": "UNSPECIFIED",
	"VERDICT_VERIFIED":    "VERIFIED",
	"VERDICT_PARTIAL":     "PARTIAL",
	"VERDICT_FAILED":      "FAILED",
}

// normalizeIssuedAt normalizes an RFC3339 / RFC3339Nano issued_at string to
// the exact form the witness assembler signs: trailing fractional-second
// zeros are stripped via time.RFC3339Nano formatting. Returns the original
// string on parse failure (fail-open).
func normalizeIssuedAt(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// DeriveSignedBytes returns the exact byte sequence the witness signs
// over for the given certificate shape. Returns a non-nil malformed
// error if any structural / invariant constraint is violated.
//
// The pipeline.go orchestrator translates malformed errors into typed
// CertificateError with ReasonMalformed; the caller should surface them
// to users via that path.
type DeriveSignedBytesInput struct {
	CertificateID          string
	RequestID              string
	ClaimRequestIDs        []string // one per claim, in order
	ClaimIDs               []string // one per claim, in order
	IssuedAt               string
	OverallVerdictFullName string // e.g. "VERDICT_VERIFIED"
	WitnessKeyID           string
}

// MalformedError is the narrow error returned by DeriveSignedBytes on
// structural issues. The orchestrator wraps it as a CertificateError with
// ReasonMalformed.
type MalformedError struct {
	Reason string
}

func (e *MalformedError) Error() string { return e.Reason }

// DeriveSignedBytes builds the exact byte sequence the witness signs for
// a v2 (7-key) signable map. v2 byte-layout is LOCKED — any change here
// breaks every v0.5.x SDK install. See TestDeriveSignedBytes_MatchesSignableFreezeHex.
func DeriveSignedBytes(in DeriveSignedBytesInput) ([]byte, error) {
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

	// The signable map mirrors assembler.go:117-125 field-for-field.
	// protocol_version: Go int 2 → JSON integer 2.
	// overall_verdict: Go short string → JSON quoted string (default path).
	// All other fields are strings or string arrays, pass-through.
	// issued_at: normalized via RFC3339Nano parse+reformat (H6 fix).
	claimIDsAny := make([]any, len(in.ClaimIDs))
	for i, id := range in.ClaimIDs {
		claimIDsAny[i] = id
	}
	signable := map[string]any{
		"certificate_id":   in.CertificateID,
		"request_id":       in.RequestID,
		"protocol_version": SignableProtocolVersion,
		"claim_ids":        claimIDsAny,
		"issued_at":        normalizeIssuedAt(in.IssuedAt),
		"overall_verdict":  goShortForm,
		"witness_key_id":   in.WitnessKeyID,
	}
	return CanonicalJSON(signable)
}
