package verify

import (
	"errors"
	"fmt"
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
	// V3SignatureStripped is true when signable_v3_signature was present but
	// the pipeline resolved to the v2 path (version absent/< 3). Always false
	// on a successful default-mode verification (the stripping guard rejects
	// such certs before reaching this point).
	V3SignatureStripped bool
	// SignedBytes are the canonical signable bytes the verified signature
	// covers (v3 or v2 per SignableVersion). Internal: the bundle verifier
	// recomputes the content-bound anchor digest from them (T-1231 S2a).
	SignedBytes []byte
	// ClaimSignaturesVerified is true when RunOptions.ServicePublicKeys was
	// supplied and every claim's own signature verified; false when no
	// service keys were supplied (claim contents were then not checked).
	ClaimSignaturesVerified bool
}

// FailureReason matches lucairn.VerifyCertificateFailureReason literals.
// Using raw strings here so internal/verify has no import cycle with the
// parent package.
type FailureReason string

const (
	ReasonMalformed                   FailureReason = "malformed"
	ReasonUnsupportedProtocolVersion  FailureReason = "unsupported_protocol_version"
	ReasonWitnessMismatch             FailureReason = "witness_mismatch"
	ReasonWitnessSignatureMissing     FailureReason = "witness_signature_missing"
	ReasonInvalidSignature            FailureReason = "invalid_signature"
	ReasonVersionDowngradeDetected    FailureReason = "version_downgrade_detected"
	ReasonSignableVersionInsufficient FailureReason = "signable_version_insufficient"
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

// RunOptions carries optional behavioral flags for Run. Zero value is safe
// and gives default backward-compatible behavior.
type RunOptions struct {
	// MinimumSignableVersion, when set to "v3", causes Run to return
	// ReasonSignableVersionInsufficient if the resolved signable version is
	// not "v3". Empty string (default) allows both v2 and v3.
	MinimumSignableVersion string
	// ServicePublicKeys, when non-nil, maps each claim-emitting service_id to
	// its Ed25519 public key (raw 32 bytes or base64 string). Run then also
	// verifies every claim's own signature over its canonical_payload and that
	// the signed payload names the same claim_id. A claim whose service has no
	// key FAILS (ReasonInvalidSignature). nil = claim contents not checked.
	ServicePublicKeys map[string]any
}

// Run executes the full verify pipeline on a raw JSON-decoded cert body.
// On success returns (Result, nil). On failure returns (_, *PipelineError).
func Run(rawCert any, keysWitnessKeyID string, keysWitnessPublicKey any, opts RunOptions) (*Result, error) {
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

	if ChainTrimSpace(parsed.WitnessSignature) == "" {
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

	// --- TOB-SDK-GO-01 (MED): downgrade stripping guard ---
	//
	// Detect partial downgrade: signable_v3_signature is present and non-empty
	// but signable_protocol_version_emitted is absent or < 3. This pattern is
	// characteristic of an active stripping attack — an adversary removed the
	// version field to force v2 dispatch, which would leave the six v3-only
	// fields (api_key_id, client_id, byok_exempt, redaction_manifest_hash,
	// sanitized_fields_body_hash, tms_manifest_hash) unverified while returning
	// "valid".
	//
	// Genuine certs:
	//   v2-only (legacy): signable_v3_signature absent/empty AND version absent.
	//   v3 dual-protocol: BOTH signable_v3_signature non-empty AND version=3.
	//
	// The combination "v3 sig present + version absent/low" is not a valid cert
	// shape; reject it unconditionally.
	v3SigPresent := ChainTrimSpace(parsed.SignableV3Signature) != ""
	if v3SigPresent && !useV3 {
		return nil, &PipelineError{
			Reason:        ReasonVersionDowngradeDetected,
			CertificateID: parsed.CertificateID,
			Message: fmt.Sprintf(
				"version downgrade detected: signable_v3_signature is present but "+
					"signable_protocol_version_emitted is %d (< 3); "+
					"this is characteristic of a stripping attack that would leave "+
					"v3-only fields (api_key_id, client_id, byok_exempt, hash fields) "+
					"unverified while returning a valid v2 signature",
				parsed.SignableProtocolVersionEmitted,
			),
		}
	}

	// Track whether a v3 sig was present when we took the v2 path. This can
	// only happen if the caller opts out of the stripping guard (which we do
	// not expose in the public API at this time; the field is reserved for
	// diagnostic use). With the guard above in place this will always be false
	// on the success path.
	v3SignatureStripped := v3SigPresent && !useV3

	var signedBytes []byte
	var signatureToVerify string
	var signableVersion string

	if useV3 {
		// v3 path: reconstruct 13-key map, verify against signable_v3_signature.
		//
		// A legitimate v3 cert ALWAYS carries a non-empty signable_v3_signature —
		// the assembler populates both on every v3 emit. A cert with
		// signable_protocol_version_emitted=3 but a missing/empty v3 sig is
		// characteristic of the other stripping direction: an adversary stripped
		// the sig (not the version) to force a v2 fallback that would skip
		// verification of the six v3-only fields. Reject as downgrade tampering
		// rather than witness_signature_missing (which implies a structural
		// malformation on an otherwise-genuine v2 cert).
		if ChainTrimSpace(parsed.SignableV3Signature) == "" {
			return nil, &PipelineError{
				Reason:        ReasonVersionDowngradeDetected,
				CertificateID: parsed.CertificateID,
				Message: fmt.Sprintf(
					"version downgrade detected: signable_protocol_version_emitted=%d "+
						"but signable_v3_signature is absent or empty; "+
						"a legitimate v3 cert always carries the v3 signature - "+
						"missing sig with version=3 is characteristic of a stripping attack "+
						"targeting the six v3-only fields (api_key_id, client_id, byok_exempt, hash fields)",
					parsed.SignableProtocolVersionEmitted,
				),
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

	// The signature text must be CANONICAL standard padded base64 (decode,
	// re-encode, compare) - the chain verifier's rule for the same fields.
	// base64.StdEncoding.DecodeString alone skips CR and LF and accepts
	// non-zero padding bits.
	// Every signature field that is PRESENT is text-checked, not only the one
	// selected for verification: on the v3 path witness_signature (non-blank,
	// decided above) must be canonical too.
	if useV3 {
		if _, okW := chainB64(parsed.WitnessSignature); !okW {
			return nil, &PipelineError{
				Reason:        ReasonInvalidSignature,
				CertificateID: parsed.CertificateID,
				Message:       "witness_signature is not canonical standard padded base64",
			}
		}
	}
	signatureBytes, ok := chainB64(signatureToVerify)
	if !ok {
		return nil, &PipelineError{
			Reason:        ReasonInvalidSignature,
			CertificateID: parsed.CertificateID,
			Message:       "witness signature is not canonical standard padded base64",
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

	// Claim signatures BEFORE the version floor, so a tampered claim
	// surfaces as invalid_signature rather than a policy verdict.
	claimsOK, claimErr := verifyClaimSignatures(parsed.CertificateID, parsed.RequestID, parsed.RawClaims, opts.ServicePublicKeys)
	if claimErr != nil {
		return nil, claimErr
	}

	anchorStatus := AnchorStatus(rawCert)
	if anchorStatus == "" {
		anchorStatus = "ANCHOR_STATUS_UNSPECIFIED"
	}

	// --- TOB-SDK-GO-01 (MED): minimum signable version enforcement ---
	//
	// When the caller requires v3 guarantees for the six additional signed
	// fields, reject any cert that resolved to v2 verification.
	if opts.MinimumSignableVersion == "v3" && signableVersion != "v3" {
		return nil, &PipelineError{
			Reason:        ReasonSignableVersionInsufficient,
			CertificateID: parsed.CertificateID,
			Message: fmt.Sprintf(
				"signable version insufficient: MinimumSignableVersion=%q but cert "+
					"resolved to signable_version=%q; "+
					"fields api_key_id, client_id, byok_exempt, redaction_manifest_hash, "+
					"sanitized_fields_body_hash, and tms_manifest_hash are NOT covered "+
					"by the witness signature on v2 certs",
				opts.MinimumSignableVersion, signableVersion,
			),
		}
	}

	return &Result{
		CertificateID:       parsed.CertificateID,
		RequestID:           parsed.RequestID,
		WitnessKeyID:        parsed.WitnessKeyID,
		IssuedAtISO:         parsed.IssuedAt,
		AnchorStatus:        anchorStatus,
		OverallVerdict:      parsed.OverallVerdict,
		SignableVersion:     signableVersion,
		V3SignatureStripped: v3SignatureStripped,
		SignedBytes:         signedBytes,

		ClaimSignaturesVerified: claimsOK,
	}, nil
}

// verifyClaimSignatures verifies every claim's own Ed25519 signature over its
// canonical_payload with the caller-supplied key of its service_id, and that
// the signed payload names the same claim_id as the (witness-signed) outer
// claim and agrees with every outer claim field (the chain verifier's steps
// 7e-7h). The witness signature covers only the claim ids, so without this a
// claim whose contents were changed after signing still verified (level-3
// review, entry 5). Returns false when serviceKeys is nil (nothing checked).
func verifyClaimSignatures(certID, requestID string, claims []any, serviceKeys map[string]any) (bool, error) {
	if serviceKeys == nil {
		return false, nil
	}
	fail := func(msg string, err error) (bool, error) {
		return false, &PipelineError{Reason: ReasonInvalidSignature, CertificateID: certID, Message: msg, Err: err}
	}
	for i, raw := range claims {
		c, _ := raw.(map[string]any)
		svc, _ := c["service_id"].(string)
		key, ok := serviceKeys[svc]
		if c == nil || !ok {
			return fail(fmt.Sprintf("claims[%d]: no service public key supplied for service_id %q", i, svc), nil)
		}
		payload, okP := chainB64(c["canonical_payload"])
		signature, okS := chainB64(c["signature"])
		if !okP || !okS {
			return fail(fmt.Sprintf("claims[%d]: canonical_payload and signature must be canonical standard padded base64", i), nil)
		}
		valid, err := VerifyEd25519(payload, signature, key)
		if err != nil {
			return fail(fmt.Sprintf("invalid service public key for %q: %v", svc, err), err)
		}
		if !valid {
			return fail(fmt.Sprintf("claims[%d] (%s): claim Ed25519 signature verification failed", i, svc), nil)
		}
		// The chain verifier's steps 7e-7h, shared code: the signed bytes are
		// ONE strict JSON object (a duplicate or case-variant key is refused),
		// name this claim_id, rebuild byte-for-byte from the OUTER fields, and
		// carry the certificate's request_id.
		doc, okDoc := SignedClaimDocument(payload)
		if !okDoc {
			return fail(fmt.Sprintf("claims[%d] (%s): signed canonical_payload is not one strict JSON object (duplicate or case-variant key, or bad grammar)", i, svc), nil)
		}
		signedID, okID := doc["claim_id"].(string)
		outerID, _ := c["claim_id"].(string)
		if !okID || signedID != outerID {
			return fail(fmt.Sprintf("claims[%d] (%s): signed canonical_payload does not name claim_id %q", i, svc, outerID), nil)
		}
		if !OuterFieldsMatchSigned(c, doc, payload) {
			return fail(fmt.Sprintf("claims[%d] (%s): an outer field (claim_id, request_id, service_id, claim_type, data_seen, data_not_seen) differs from the signed canonical_payload", i, svc), nil)
		}
		// The outer timestamp is written in another textual form than the
		// signed one (protojson pads fractions to 3/6/9 digits), so it is
		// compared as an instant with the chain's ONE timestamp grammar.
		if outerTS, present := c["timestamp"]; present && outerTS != nil {
			ots, okO := outerTS.(string)
			ss, okS := doc["timestamp"].(string)
			a, okA := ChainIssuedAt(ots)
			b, okB := ChainIssuedAt(ss)
			if !okO || !okS || !okA || !okB || a != b {
				return fail(fmt.Sprintf("claims[%d] (%s): outer timestamp differs from the signed canonical_payload", i, svc), nil)
			}
		}
		if signedReq, _ := doc["request_id"].(string); signedReq != requestID {
			return fail(fmt.Sprintf("claims[%d] (%s): signed canonical_payload names another request_id than the certificate", i, svc), nil)
		}
	}
	return true, nil
}
