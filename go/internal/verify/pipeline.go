package verify

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// SupportedProtocolVersion is the only protocol version v1 of the SDK
// knows how to verify. Certificates with a different protocol_version
// surface as a typed unsupported_protocol_version error. Mirrors
// SignableProtocolVersion (must update together).
const SupportedProtocolVersion = SignableProtocolVersion

// Result mirrors the SDK-level VerifyCertificateResult shape; the public
// wrapper in the parent package re-wraps it with its own type so the
// public API doesn't leak internal/verify.
type Result struct {
	CertificateID  string
	RequestID      string
	WitnessKeyID   string
	IssuedAtISO    string
	AnchorStatus   string
	OverallVerdict string
	// SignableVersion is "v2" when the witness signature was verified against
	// the 7-key v2 signable map, or "v3" when verified against the 13-key v3
	// map. Corresponds to PRD criterion #7. Empty only on unexpected internal
	// paths (should never happen in practice).
	SignableVersion string
}

// FailureReason matches lucairn.VerifyCertificateFailureReason literals.
// Using raw strings here so internal/verify has no import cycle with the
// parent package.
type FailureReason string

const (
	ReasonMalformed                  FailureReason = "malformed"
	ReasonUnsupportedProtocolVersion FailureReason = "unsupported_protocol_version"
	ReasonWitnessMismatch            FailureReason = "witness_mismatch"
	ReasonWitnessSignatureMissing    FailureReason = "witness_signature_missing"
	ReasonInvalidSignature           FailureReason = "invalid_signature"
)

// PipelineError is the typed error returned by Run. The parent package
// rewraps it as lucairn.CertificateError for external callers.
type PipelineError struct {
	Reason        FailureReason
	CertificateID string
	Message       string
	Err           error
}

func (e *PipelineError) Error() string { return e.Message }
func (e *PipelineError) Unwrap() error { return e.Err }

// Run executes the full verify pipeline on a raw JSON-decoded cert body.
// On success returns (Result, nil). On failure returns (_, *PipelineError).
func Run(rawCert any, keysWitnessKeyID string, keysWitnessPublicKey any) (*Result, error) {
	parsed, err := Parse(rawCert)
	if err != nil {
		var em *ErrParseMalformed
		if errors.As(err, &em) {
			return nil, &PipelineError{
				Reason:        ReasonMalformed,
				CertificateID: em.CertificateID,
				Message:       em.Reason,
				Err:           err,
			}
		}
		return nil, &PipelineError{
			Reason:  ReasonMalformed,
			Message: err.Error(),
			Err:     err,
		}
	}

	if parsed.ProtocolVersion != SupportedProtocolVersion {
		return nil, &PipelineError{
			Reason:        ReasonUnsupportedProtocolVersion,
			CertificateID: parsed.CertificateID,
			Message: fmt.Sprintf("unsupported Veil protocol version: %d (SDK supports %d)",
				parsed.ProtocolVersion, SupportedProtocolVersion),
		}
	}

	if parsed.WitnessKeyID != keysWitnessKeyID {
		return nil, &PipelineError{
			Reason:        ReasonWitnessMismatch,
			CertificateID: parsed.CertificateID,
			Message: fmt.Sprintf("witness key ID mismatch: cert has %q, expected %q",
				parsed.WitnessKeyID, keysWitnessKeyID),
		}
	}

	if strings.TrimSpace(parsed.WitnessSignature) == "" {
		return nil, &PipelineError{
			Reason:        ReasonWitnessSignatureMissing,
			CertificateID: parsed.CertificateID,
			Message:       "certificate has no witness signature",
		}
	}

	// --- Version dispatch ---
	//
	// signable_protocol_version_emitted >= 3 → verify v3 (13-key) against
	// signable_v3_signature. v2 signable bytes are STILL correct (witness
	// mirrors witness_signature to signable_v2_signature byte-for-byte) but
	// for v3 certs we prefer the richer v3 verification path so the caller
	// sees SignableVersion="v3" (PRD criterion #7).
	//
	// signable_protocol_version_emitted <= 0 (absent) or < 3 → v2 path:
	// reconstruct 7-key map, verify against witness_signature.
	//
	// Backward compat guarantee (criterion #8): v2 signature == witness_signature
	// on all v3 certs, so an old SDK using witness_signature still verifies.
	// New SDKs use the explicit v3 path for v3 certs.
	useV3 := parsed.SignableProtocolVersionEmitted >= 3

	var signedBytes []byte
	var signatureToVerify string
	var signableVersion string

	if useV3 {
		// v3 path: reconstruct 13-key map, verify against signable_v3_signature.
		if strings.TrimSpace(parsed.SignableV3Signature) == "" {
			return nil, &PipelineError{
				Reason:        ReasonWitnessSignatureMissing,
				CertificateID: parsed.CertificateID,
				Message:       "cert carries signable_protocol_version_emitted=3 but signable_v3_signature is absent",
			}
		}
		var v3err error
		signedBytes, v3err = DeriveV3SignedBytes(DeriveV3SignedBytesInput{
			CertificateID:           parsed.CertificateID,
			RequestID:               parsed.RequestID,
			ClaimRequestIDs:         parsed.ClaimRequestIDs,
			ClaimIDs:                parsed.ClaimIDs,
			IssuedAt:                parsed.IssuedAt,
			OverallVerdictFullName:  parsed.OverallVerdict,
			WitnessKeyID:            parsed.WitnessKeyID,
			ClientID:                parsed.ClientID,
			APIKeyID:                parsed.APIKeyID,
			ByokExempt:              parsed.ByokExempt,
			RedactionManifestHash:   ExtractSanitizerPayloadHash(parsed.RawClaims, "redaction_manifest_hash"),
			SanitizedFieldsBodyHash: ExtractSanitizerPayloadHash(parsed.RawClaims, "sanitized_fields_hash"),
			TMSManifestHash:         ExtractSanitizerPayloadHash(parsed.RawClaims, "tms_manifest_hash"),
		})
		if v3err != nil {
			var me *MalformedError
			if errors.As(v3err, &me) {
				return nil, &PipelineError{
					Reason:        ReasonMalformed,
					CertificateID: parsed.CertificateID,
					Message:       me.Reason,
					Err:           v3err,
				}
			}
			return nil, &PipelineError{
				Reason:        ReasonMalformed,
				CertificateID: parsed.CertificateID,
				Message:       "failed to derive v3 signed payload: " + v3err.Error(),
				Err:           v3err,
			}
		}
		signatureToVerify = parsed.SignableV3Signature
		signableVersion = "v3"
	} else {
		// v2 path: reconstruct 7-key map, verify against witness_signature.
		var v2err error
		signedBytes, v2err = DeriveSignedBytes(DeriveSignedBytesInput{
			CertificateID:          parsed.CertificateID,
			RequestID:              parsed.RequestID,
			ClaimRequestIDs:        parsed.ClaimRequestIDs,
			ClaimIDs:               parsed.ClaimIDs,
			IssuedAt:               parsed.IssuedAt,
			OverallVerdictFullName: parsed.OverallVerdict,
			WitnessKeyID:           parsed.WitnessKeyID,
		})
		if v2err != nil {
			var me *MalformedError
			if errors.As(v2err, &me) {
				return nil, &PipelineError{
					Reason:        ReasonMalformed,
					CertificateID: parsed.CertificateID,
					Message:       me.Reason,
					Err:           v2err,
				}
			}
			return nil, &PipelineError{
				Reason:        ReasonMalformed,
				CertificateID: parsed.CertificateID,
				Message:       "failed to derive signed payload: " + v2err.Error(),
				Err:           v2err,
			}
		}
		signatureToVerify = parsed.WitnessSignature
		signableVersion = "v2"
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signatureToVerify)
	if err != nil {
		return nil, &PipelineError{
			Reason:        ReasonInvalidSignature,
			CertificateID: parsed.CertificateID,
			Message:       "witness signature base64 decode failed: " + err.Error(),
			Err:           err,
		}
	}

	valid, err := VerifyEd25519(signedBytes, signatureBytes, keysWitnessPublicKey)
	if err != nil {
		return nil, &PipelineError{
			Reason:        ReasonInvalidSignature,
			CertificateID: parsed.CertificateID,
			Message:       "invalid witness_public_key: " + err.Error(),
			Err:           err,
		}
	}
	if !valid {
		return nil, &PipelineError{
			Reason:        ReasonInvalidSignature,
			CertificateID: parsed.CertificateID,
			Message:       "witness Ed25519 signature verification failed",
		}
	}

	anchorStatus := AnchorStatus(rawCert)
	if anchorStatus == "" {
		anchorStatus = "ANCHOR_STATUS_UNSPECIFIED"
	}

	return &Result{
		CertificateID:   parsed.CertificateID,
		RequestID:       parsed.RequestID,
		WitnessKeyID:    parsed.WitnessKeyID,
		IssuedAtISO:     parsed.IssuedAt,
		AnchorStatus:    anchorStatus,
		OverallVerdict:  parsed.OverallVerdict,
		SignableVersion: signableVersion,
	}, nil
}
