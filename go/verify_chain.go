package lucairn

import (
	"crypto/ed25519"
	"fmt"

	"github.com/declade/lucairn-sdks/go/internal/verify"
)

// CertificateChainKeys are the pinned trust roots for VerifyCertificateChain.
type CertificateChainKeys struct {
	// WitnessKeyID is the witness key_id the certificate must name.
	WitnessKeyID string
	// WitnessPublicKey is a raw 32-byte Ed25519 key ([]byte) or a base64
	// string encoding those 32 bytes.
	WitnessPublicKey any
	// ServicePublicKeys pins one Ed25519 key per claim-emitting service_id
	// (e.g. "dsa-sanitizer", "dsa-ai", "dsa-gateway", "dsa-bridge",
	// "dsa-audit", "dsa-reid-guard"), each as []byte or base64 string. A
	// claim from a service with no pinned key FAILS the certificate
	// (reason "unknown_service"); it is never skipped.
	ServicePublicKeys map[string]any
	// MinimumSignableVersion selects the policy: "" or "v2" = "default"
	// (legacy-tolerant: v2-only certificates verify, and their v3-only fields
	// are listed in UnauthenticatedFields); "v3" = "minimum_v3" (a
	// certificate that authenticates only through the v2 signable FAILS with
	// reason "signable_version_insufficient").
	MinimumSignableVersion string
}

// CertificateChainResult is the result of VerifyCertificateChain. The JSON
// field names and every value are the parity corpus README § Result's.
type CertificateChainResult struct {
	// Verdict: "FAILED" < "PARTIAL" < "EGRESS_UNATTESTED" < "VERIFIED".
	// Only "VERIFIED" is green; "EGRESS_UNATTESTED" never is.
	Verdict string `json:"verdict"`
	// Reason is the reason of the recipe step that decided.
	Reason string `json:"reason"`
	// EgressAttestation: "signed_digests" | "unattested" | "not_evaluated".
	EgressAttestation string `json:"egress_attestation"`
	// UserUnredacted is the STRING "true" | "false" | "unknown" (every FAILED
	// result), read from the verified, signed sanitizer payload only.
	// Compare it to "true".
	UserUnredacted string `json:"user_unredacted"`
	// SignedCertTier: "absent" | "input_shield" | "inconsistent" |
	// "not_evaluated". Show THIS tier, never the unsigned
	// verification.cert_tier.
	SignedCertTier string `json:"signed_cert_tier"`
	// SignableVersion: "v3" | "v2" | "none".
	SignableVersion string `json:"signable_version"`
	// AuthenticatedFields are the witness-signable keys that authenticated
	// the certificate metadata (sorted).
	AuthenticatedFields []string `json:"authenticated_fields"`
	// UnauthenticatedFields are fields NO signature covers (sorted). Every
	// entry MUST be labelled unverified wherever it is displayed and MUST
	// NEVER be the basis of a decision (not a BYOK / "sent unredacted" mark,
	// not a client or API-key attribution, not a model claim).
	UnauthenticatedFields []string `json:"unauthenticated_fields"`
}

// VerifyCertificateChain verifies a Lucairn certificate AND every claim
// inside it (T-935 S3 / T-794).
//
// VerifyCertificate checks the witness signatures only: a certificate whose
// claim body was edited under the same claim id still passes it. This
// function runs the full parity-corpus recipe (Declade/dual-sandbox-
// architecture tools/parity-corpus/README.md § Verification recipe; its check
// table is vendored at testdata/parity-corpus/recipe-table.md): the witness signatures, every claim's
// signature against its pinned service key, the canonical-bytes rebuild,
// claim-id membership, the typed-field binding, the signed egress digests,
// the unsigned cert_tier against its signed copies, and the signed
// user_unredacted_segment token.
//
// certificate is the certificate JSON exactly as received (the raw body of
// GET /api/v1/veil/certificate/{id}, or a witness export) — raw bytes, not a
// re-marshalled struct: integer tokens, float lexemes and trailing data are
// part of the checks.
//
// Certificate problems are a FAILED result, never an error. The error is a
// *ConfigError for programmer errors only (a malformed key set or policy).
func VerifyCertificateChain(certificate []byte, keys CertificateChainKeys) (*CertificateChainResult, error) {
	if keys.WitnessKeyID == "" {
		return nil, &ConfigError{Message: "CertificateChainKeys.WitnessKeyID must be non-empty"}
	}
	var minV3 bool
	switch keys.MinimumSignableVersion {
	case "", "v2":
	case "v3":
		minV3 = true
	default:
		return nil, &ConfigError{Message: fmt.Sprintf("CertificateChainKeys.MinimumSignableVersion must be \"\", \"v2\" or \"v3\", got %q", keys.MinimumSignableVersion)}
	}
	witness, err := verify.NormalizeEd25519PublicKey(keys.WitnessPublicKey)
	if err != nil {
		return nil, &ConfigError{Message: "CertificateChainKeys.WitnessPublicKey: " + err.Error()}
	}
	services := make(map[string]ed25519.PublicKey, len(keys.ServicePublicKeys))
	for svc, k := range keys.ServicePublicKeys {
		if svc == "" {
			return nil, &ConfigError{Message: "CertificateChainKeys.ServicePublicKeys: empty service_id"}
		}
		raw, err := verify.NormalizeEd25519PublicKey(k)
		if err != nil {
			return nil, &ConfigError{Message: fmt.Sprintf("CertificateChainKeys.ServicePublicKeys[%q]: %s", svc, err.Error())}
		}
		services[svc] = ed25519.PublicKey(raw)
	}
	r := verify.RunChain(certificate, verify.ChainKeys{
		WitnessKeyID: keys.WitnessKeyID,
		Witness:      ed25519.PublicKey(witness),
		Services:     services,
	}, minV3)
	return &CertificateChainResult{
		Verdict:               r.Verdict,
		Reason:                r.Reason,
		EgressAttestation:     r.EgressAttestation,
		UserUnredacted:        r.UserUnredacted,
		SignedCertTier:        r.SignedCertTier,
		SignableVersion:       r.SignableVersion,
		AuthenticatedFields:   r.AuthenticatedFields,
		UnauthenticatedFields: r.UnauthenticatedFields,
	}, nil
}
