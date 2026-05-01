package theveil

import (
	"encoding/json"
	"errors"
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

	result, runErr := verify.Run(rawAny, keys.WitnessKeyID, keys.WitnessPublicKey)
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
		var out any
		if err := json.Unmarshal(v, &out); err != nil {
			return nil, &CertificateError{
				Reason:  ReasonMalformed,
				Message: "failed to parse certificate bytes as JSON: " + err.Error(),
				Err:     err,
			}
		}
		return out, nil
	case json.RawMessage:
		var out any
		if err := json.Unmarshal(v, &out); err != nil {
			return nil, &CertificateError{
				Reason:  ReasonMalformed,
				Message: "failed to parse certificate RawMessage as JSON: " + err.Error(),
				Err:     err,
			}
		}
		return out, nil
	case string:
		return v, nil // let Parse reject as "not a JSON object"
	default:
		// Pass through — Parse will reject anything it doesn't know.
		return v, nil
	}
}
