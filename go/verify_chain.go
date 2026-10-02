package lucairn

import (
	"crypto/ed25519"
	"fmt"
	"sort"

	"github.com/declade/lucairn-sdks/go/internal/verify"
)

// CertificateChainKeys are the pinned trust roots and the options for
// VerifyCertificateChain.
//
// Every pinned key passes the pinned-key policy when VerifyCertificateChain
// loads it; a refused key is a *KeyPolicyError (a caller error, never a
// verdict).
type CertificateChainKeys struct {
	// WitnessKeyID is the witness key_id the certificate must name.
	WitnessKeyID string
	// WitnessPublicKey is the witness Ed25519 key: a raw 32-byte []byte, or
	// a string holding the CANONICAL standard padded base64 of those 32
	// bytes (no hex, no URL-safe alphabet, no missing padding, no whitespace
	// or line break, no set trailing bits).
	WitnessPublicKey any
	// ServicePublicKeys pins one Ed25519 key per claim-emitting service_id
	// (e.g. "dsa-sanitizer", "dsa-ai", "dsa-gateway", "dsa-bridge",
	// "dsa-audit", "dsa-reid-guard", "dsa-sanitizer-streaming"), each in the
	// same form as WitnessPublicKey. A claim from a service with no pinned
	// key FAILS the certificate (reason "unknown_service"); it is never
	// skipped.
	ServicePublicKeys map[string]any
	// MinimumSignableVersion selects the policy: "" or "v2" = "default"
	// (legacy-tolerant: a certificate that carries only the older v2 witness
	// signature verifies, and Verified.Certificate then holds only the 7 v2
	// keys); "v3" = "minimum_v3" (such a certificate FAILS with reason
	// "signable_version_insufficient").
	MinimumSignableVersion string
	// ExpectedRequestID / ExpectedCertificateID bind the certificate to the
	// turn the caller asked about: each supplied value must equal the
	// witness-signed request_id / certificate_id, else the result is FAILED
	// "request_mismatch". nil = not supplied; a pointer to "" IS a supplied
	// value. Always pass the request id of the turn you are showing: without
	// it, a genuine certificate of ANOTHER turn (a store, fetch-path or relay
	// swap) verifies. It does not stop a compromised gateway or local proxy,
	// which hands out the request id in the first place.
	ExpectedRequestID     *string
	ExpectedCertificateID *string
	// AllowTestKeys lets the published parity-corpus test keys load. Their
	// private keys follow from a public seed, so a product must never set
	// it; only a parity test harness does.
	AllowTestKeys bool
}

// KeyPolicyError is returned by VerifyCertificateChain when a pinned key is
// refused (the equivalent of PinnedKeyError in the TS and Python SDKs). Code is one of "key_malformed", "key_small_order",
// "key_invalid_point", "key_test_key" (checked in that order); Key names the
// key ("witness" or the service_id).
type KeyPolicyError struct {
	Code string
	Key  string
}

func (e *KeyPolicyError) Error() string {
	return fmt.Sprintf("lucairn: pinned key %q rejected: %s", e.Key, e.Code)
}

func (e *KeyPolicyError) lucairnError() {}

// CertificateChainResult is the result of VerifyCertificateChain. The JSON
// field names and every value are the parity corpus result's.
//
// Render and decide ONLY from Verified plus Verdict, Reason,
// EgressAttestation, SignedCertTier, UserUnredacted and RequestBinding —
// never from the raw certificate and never from a second parse of it (a
// re-parse, for example json.Unmarshal into VeilCertificate, can read a
// field no signature covers). What is not in Verified is not verified.
type CertificateChainResult struct {
	// Verdict: "FAILED" < "PARTIAL" < "EGRESS_UNATTESTED" < "VERIFIED".
	// Only "VERIFIED" is green; "EGRESS_UNATTESTED" never is. This is the
	// verdict to display — never Verified.Certificate["overall_verdict"],
	// which is what the witness sealed.
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
	// "not_evaluated", or "input_shield_two_signer" (an input-shield chain
	// with only sanitizer + gateway claims: exactly one signed tier copy,
	// from the gateway, at least one dsa-sanitizer claim, and no dsa-ai
	// claim; never green, as it carries no signed egress digests), or
	// "audit_only" (corpus v1.2.2+: a certificate-only chain whose one dsa-ai
	// claim signs cert_tier "audit-only" — the content was NOT sanitized, by
	// design; a VERIFIED audit_only result attests what was sent, never that
	// anything was sanitized, and must be shown that way). Show THIS tier,
	// never the unsigned verification.cert_tier.
	SignedCertTier string `json:"signed_cert_tier"`
	// SignableVersion: "v3" | "v2" | "none".
	SignableVersion string `json:"signable_version"`
	// RequestBinding: "matched" (ExpectedRequestID and/or
	// ExpectedCertificateID supplied and equal to the signed values),
	// "not_checked" (none supplied) or "not_evaluated" (every FAILED result).
	RequestBinding string `json:"request_binding"`
	// Verified holds the values the signatures cover, and nothing else; nil
	// (JSON null) on every FAILED result.
	Verified *VerifiedChain `json:"verified"`
}

// VerifiedChain is built ONLY from signed bytes.
type VerifiedChain struct {
	// Certificate is the witness signable map whose signature verified, key
	// for key: certificate_id, claim_ids, issued_at (UTC signable form),
	// overall_verdict (without "VERDICT_"), protocol_version (json.Number
	// "2"), request_id, witness_key_id; under signable version v3 also
	// api_key_id, byok_exempt, client_id, redaction_manifest_hash,
	// sanitized_fields_body_hash, tms_manifest_hash. Values are string, bool,
	// json.Number, []any (of strings) or nil (JSON null). A v3-only value
	// (client, API key, BYOK) is ABSENT under v2: never show it then.
	Certificate map[string]any `json:"certificate"`
	// Claims has one entry per claim, keyed
	// "<index>:<service_id>:<claim_type>" (index = position in claims[],
	// decimal; claim_type = the SIGNED type, "" for an unnamed one). The
	// claim type never contains ':', so split at the first and the last ':'.
	// Order claims by the parsed index, not by key.
	Claims map[string]VerifiedClaim `json:"claims"`
}

// VerifiedClaim is one verified claim.
type VerifiedClaim struct {
	// Canonical is the claim's signed canonical bytes, exactly: everything
	// the claim signs (floats included) is in it.
	Canonical string `json:"canonical"`
	// Values maps the RFC 6901 JSON Pointer (from the signed document root:
	// "/payload/model_used", "/data_seen/0") of every string, boolean and
	// integer-token leaf to its value: string, bool, or json.Number (an
	// integer of up to 20 digits, at most 2^64-1; keep its text). null,
	// floats, negative numbers and empty containers have no entry — read
	// them from Canonical.
	Values map[string]any `json:"values"`
}

// VerifyCertificateChain verifies a Lucairn certificate AND every claim
// inside it.
//
// VerifyCertificate checks the witness signatures only: a certificate whose
// claim body was edited under the same claim id still passes it. This
// function runs the full recipe of the Lucairn certificate verifier parity
// corpus (its ordered check table is vendored at
// testdata/parity-corpus/recipe-table.md): the witness signatures, the
// optional request binding, every claim's signature against its pinned
// service key, the canonical-bytes rebuild, claim-id membership, the
// typed-field binding, the signed egress digests, the unsigned cert_tier
// against its signed copies, and the signed user_unredacted_segment token.
// The result's Verified carries the signed values and nothing else.
//
// certificate is the certificate JSON exactly as received (the raw body of
// GET /api/v1/veil/certificate/{id}, or a witness export) — raw bytes, not a
// re-marshalled struct: integer tokens, float lexemes, duplicate keys and
// trailing data are part of the checks. Inputs above 32 MiB are malformed.
//
// Certificate problems are a FAILED result, never an error. The error is a
// *KeyPolicyError for a refused pinned key, or a *ConfigError for another
// programmer error (an empty WitnessKeyID or service id, an unknown policy).
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
	witness, code := verify.PinnedChainKey(keys.WitnessPublicKey, keys.AllowTestKeys)
	if code != verify.KeyPolicyOK {
		return nil, &KeyPolicyError{Code: code, Key: "witness"}
	}
	svcIDs := make([]string, 0, len(keys.ServicePublicKeys))
	for svc := range keys.ServicePublicKeys {
		if svc == "" {
			return nil, &ConfigError{Message: "CertificateChainKeys.ServicePublicKeys: empty service_id"}
		}
		svcIDs = append(svcIDs, svc)
	}
	sort.Strings(svcIDs) // a deterministic first refusal
	services := make(map[string]ed25519.PublicKey, len(svcIDs))
	for _, svc := range svcIDs {
		pub, code := verify.PinnedChainKey(keys.ServicePublicKeys[svc], keys.AllowTestKeys)
		if code != verify.KeyPolicyOK {
			return nil, &KeyPolicyError{Code: code, Key: svc}
		}
		services[svc] = pub
	}
	r := verify.RunChain(certificate, verify.ChainKeys{
		WitnessKeyID: keys.WitnessKeyID,
		Witness:      witness,
		Services:     services,
	}, minV3, verify.ChainInputs{
		ExpectedRequestID:     keys.ExpectedRequestID,
		ExpectedCertificateID: keys.ExpectedCertificateID,
	})
	out := &CertificateChainResult{
		Verdict:           r.Verdict,
		Reason:            r.Reason,
		EgressAttestation: r.EgressAttestation,
		UserUnredacted:    r.UserUnredacted,
		SignedCertTier:    r.SignedCertTier,
		SignableVersion:   r.SignableVersion,
		RequestBinding:    r.RequestBinding,
	}
	if r.Verified != nil {
		v := &VerifiedChain{Certificate: r.Verified.Certificate, Claims: make(map[string]VerifiedClaim, len(r.Verified.Claims))}
		for k, c := range r.Verified.Claims {
			v.Claims[k] = VerifiedClaim{Canonical: c.Canonical, Values: c.Values}
		}
		out.Verified = v
	}
	return out, nil
}
