package lucairn

import (
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/verify"
)

// VerifyCertificate verifies a Veil Certificate's witness Ed25519 signature
// against the certificate's canonical-JSON signed subset.
//
// External RFC 3161 timestamp verification and Sigstore Rekor
// transparency-log verification are OUT OF SCOPE for this SDK release;
// they land in a follow-up arc pending gateway fixes. The result surfaces
// AnchorStatus and OverallVerdict as pass-through metadata — the SDK does
// NOT independently verify them.
//
// On failure returns a *CertificateError. On keys nil / wrong-type input
// returns a *ConfigError (programmer error, not a cert-verification
// failure).
//
// cert may be passed as *VeilCertificate (when you already have the
// parsed object from GetCertificate), as any (e.g. map[string]any from a
// json.Unmarshal), or as []byte / json.RawMessage (raw response body).
// All three forms normalize to the same internal representation.
//
// Given an already parsed object (map or struct), the simple check judges
// values; number-token rules apply only where the SDK reads the raw text (Go
// with raw bytes; the chain verifier in all three SDKs). With []byte or
// json.RawMessage input, protocol_version and
// signable_protocol_version_emitted must be integer tokens (digits only, at
// most 2^64-1), else ReasonMalformed: 2.0, 2e0 or 2.0000000000000001 are
// refused there, while a map holding float64(2) is accepted.
func VerifyCertificate(cert any, keys VerifyCertificateKeys) (*VerifyCertificateResult, error) {
	if keys.WitnessKeyID == "" {
		return nil, &ConfigError{Message: "VerifyCertificateKeys.WitnessKeyID must be non-empty"}
	}
	if keys.WitnessPublicKey == nil {
		return nil, &ConfigError{Message: "VerifyCertificateKeys.WitnessPublicKey must be non-nil"}
	}

	rawAny, err := normalizeCertInput(cert)
	if err != nil {
		return nil, err
	}

	result, runErr := verify.Run(rawAny, keys.WitnessKeyID, keys.WitnessPublicKey, verify.RunOptions{
		MinimumSignableVersion: keys.MinimumSignableVersion,
	})
	if runErr != nil {
		var pe *verify.PipelineError
		if errors.As(runErr, &pe) {
			return nil, &CertificateError{
				Reason:        VerifyCertificateFailureReason(pe.Reason),
				CertificateID: pe.CertificateID,
				Message:       pe.Message,
				Err:           pe.Err,
			}
		}
		return nil, &CertificateError{
			Reason:  ReasonMalformed,
			Message: runErr.Error(),
			Err:     runErr,
		}
	}

	// Best-effort parse of the witness-asserted ISO string into time.Time.
	// If parse fails (malformed-but-signed timestamp — theoretically
	// possible under a compromised witness; the Go assembler in practice
	// always emits RFC3339Nano), leave the zero-value. Callers requiring
	// definitive precision should prefer WitnessAssertedIssuedAtISO.
	parsed, _ := time.Parse(time.RFC3339Nano, result.IssuedAtISO)

	return &VerifyCertificateResult{
		CertificateID:              result.CertificateID,
		RequestID:                  result.RequestID,
		WitnessKeyID:               result.WitnessKeyID,
		WitnessAssertedIssuedAt:    parsed,
		WitnessAssertedIssuedAtISO: result.IssuedAtISO,
		AnchorStatus:               VeilCertAnchorStatus(result.AnchorStatus),
		OverallVerdict:             VeilVerdict(result.OverallVerdict),
		SignableVersion:            result.SignableVersion,
		V3SignatureStripped:        result.V3SignatureStripped,
	}, nil
}

// normalizeCertInput accepts the three common input shapes and returns a
// generic any that internal/verify.Parse understands.
func normalizeCertInput(cert any) (any, error) {
	switch v := cert.(type) {
	case nil:
		return nil, nil // let Parse surface the "not a JSON object" malformed
	case map[string]any:
		return v, nil
	case *VeilCertificate:
		if v == nil {
			return nil, nil
		}
		// Round-trip through JSON to produce the map[string]any shape
		// internal/verify.Parse expects. json.Marshal on our struct
		// produces the protojson-shaped bytes (because our json tags
		// match), and Unmarshal into any produces map[string]any.
		b, err := json.Marshal(v)
		if err != nil {
			return nil, &CertificateError{
				Reason:  ReasonMalformed,
				Message: "failed to marshal *VeilCertificate for verify: " + err.Error(),
				Err:     err,
			}
		}
		var out any
		if err := json.Unmarshal(b, &out); err != nil {
			return nil, &CertificateError{
				Reason:  ReasonMalformed,
				Message: "failed to unmarshal *VeilCertificate for verify: " + err.Error(),
				Err:     err,
			}
		}
		return out, nil
	case []byte:
		return decodeCertText(v, "bytes")
	case json.RawMessage:
		return decodeCertText(v, "RawMessage")
	case string:
		return v, nil // let Parse reject as "not a JSON object"
	default:
		// Pass through — Parse will reject anything it doesn't know.
		return v, nil
	}
}

// certIntegerFields are the integers the witness-only check reads.
var certIntegerFields = []string{"protocol_version", "signable_protocol_version_emitted"}

// decodeCertText decodes a certificate given as raw JSON text. The generic
// decode is the one a caller's own json.Unmarshal would do (numbers as
// float64), so everything downstream sees the same values as with map input
// (the two integer fields below are handed on as their exact tokens).
// In addition, because the text is in hand here, the integers the check reads
// must be written as integer TOKENS (digits only, at most 20 digits, at most
// 2^64-1): a float64 decode would round 2.0000000000000001 to 2. Map and
// *VeilCertificate input carry no tokens and are judged by value.
func decodeCertText(b []byte, kind string) (any, error) {
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, &CertificateError{
			Reason:  ReasonMalformed,
			Message: "failed to parse certificate " + kind + " as JSON: " + err.Error(),
			Err:     err,
		}
	}
	if _, isObject := out.(map[string]any); !isObject {
		return out, nil // Parse reports "not a JSON object"
	}
	var tokens map[string]json.RawMessage
	if err := json.Unmarshal(b, &tokens); err != nil {
		return nil, &CertificateError{
			Reason:  ReasonMalformed,
			Message: "failed to parse certificate " + kind + " as JSON: " + err.Error(),
			Err:     err,
		}
	}
	for _, field := range certIntegerFields {
		tok := tokens[field]
		if len(tok) == 0 || !(tok[0] == '-' || (tok[0] >= '0' && tok[0] <= '9')) {
			continue // absent or not a number: Parse decides, as for map input
		}
		if _, ok := verify.ChainInteger(json.Number(string(tok)), math.MaxUint64); !ok {
			certID, _ := out.(map[string]any)["certificate_id"].(string)
			return nil, &CertificateError{
				Reason:        ReasonMalformed,
				CertificateID: certID,
				Message:       field + " must be written as an integer token in [0, 2^64-1]",
			}
		}
		// Hand the exact token on for this field only, so the value rule is
		// decided on the token (2^64-1 is not a float64) and never on a
		// rounded float64. Nothing else in the decoded map changes.
		out.(map[string]any)[field] = json.Number(string(tok))
	}
	return out, nil
}
