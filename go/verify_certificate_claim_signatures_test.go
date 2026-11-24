package lucairn

// Claim-signature check of the simple VerifyCertificate (security fix stream
// T-1474, slice F16; level-3 review entry 5: "the SDK's certificate check
// reports valid for a certificate whose claim contents were changed").
//
// The witness signature covers only the list of claim ids. With
// keys.ServicePublicKeys supplied, VerifyCertificate must also verify each
// claim's own Ed25519 signature over its canonical_payload. Synthetic keys and
// data only.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/declade/lucairn-sdks/go/internal/verify"
)

type f16Pair struct {
	priv ed25519.PrivateKey
	pub  string
}

func f16NewPair(t *testing.T) f16Pair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return f16Pair{priv: priv, pub: base64.StdEncoding.EncodeToString(pub)}
}

func f16SignedClaim(t *testing.T, p f16Pair, claimID, serviceID, claimType string, payload map[string]any) map[string]any {
	t.Helper()
	// The gateway signs the short claim-type name (the chain recipe's step 7g).
	cp, err := json.Marshal(map[string]any{
		"claim_id":      claimID,
		"claim_type":    strings.TrimPrefix(claimType, "CLAIM_TYPE_"),
		"data_not_seen": []any{},
		"data_seen":     []any{},
		"payload":       payload,
		"request_id":    "req_f16_0001",
		"service_id":    serviceID,
		"timestamp":     "2026-11-21T08:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"claim_id":          claimID,
		"request_id":        "req_f16_0001",
		"service_id":        serviceID,
		"claim_type":        claimType,
		"data_seen":         []any{},
		"data_not_seen":     []any{},
		"canonical_payload": base64.StdEncoding.EncodeToString(cp),
		"timestamp":         "2026-11-21T08:00:00Z",
		"signature":         base64.StdEncoding.EncodeToString(ed25519.Sign(p.priv, cp)),
	}
}

type f16Keys struct{ witness, bridge, sanitizer f16Pair }

func f16Cert(t *testing.T, k f16Keys, v3 bool) map[string]any {
	t.Helper()
	m := map[string]any{
		"certificate_id":   "veil_f16_0001",
		"request_id":       "req_f16_0001",
		"protocol_version": float64(2),
		"claims": []any{
			f16SignedClaim(t, k.bridge, "clm_f16_bridge", "dsa-bridge", "CLAIM_TYPE_TOKEN_GENERATED",
				map[string]any{"org_id": "org_synthetic"}),
			f16SignedClaim(t, k.sanitizer, "clm_f16_sanitizer", "dsa-sanitizer", "CLAIM_TYPE_PII_SANITIZED",
				map[string]any{"entities_found": float64(3), "redaction_manifest_hash": "aGFzaA=="}),
		},
		"verification": map[string]any{
			"signatures_valid":           true,
			"completeness":               "COMPLETENESS_FULL",
			"missing_services":           []any{},
			"temporal_consistent":        true,
			"data_visibility_consistent": true,
			"isolation_verified":         true,
			"qi_score":                   nil,
			"overall_verdict":            "VERDICT_VERIFIED",
		},
		"issued_at":         "2026-11-21T08:00:01Z",
		"witness_signature": "AAAA",
		"witness_key_id":    "witness_f16",
	}
	p, err := verify.Parse(m)
	if err != nil {
		t.Fatal(err)
	}
	v2, err := verify.DeriveSignedBytes(verify.DeriveSignedBytesInput{
		CertificateID: p.CertificateID, RequestID: p.RequestID, ClaimRequestIDs: p.ClaimRequestIDs,
		ClaimIDs: p.ClaimIDs, IssuedAt: p.IssuedAt, OverallVerdictFullName: p.OverallVerdict, WitnessKeyID: p.WitnessKeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	m["witness_signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(k.witness.priv, v2))
	if v3 {
		v3b, err := verify.DeriveV3SignedBytes(verify.DeriveV3SignedBytesInput{
			CertificateID: p.CertificateID, RequestID: p.RequestID, ClaimRequestIDs: p.ClaimRequestIDs,
			ClaimIDs: p.ClaimIDs, IssuedAt: p.IssuedAt, OverallVerdictFullName: p.OverallVerdict, WitnessKeyID: p.WitnessKeyID,
			ClientID: p.ClientID, APIKeyID: p.APIKeyID, ByokExempt: p.ByokExempt,
			RedactionManifestHash:   verify.ExtractSanitizerPayloadHash(p.RawClaims, "redaction_manifest_hash"),
			SanitizedFieldsBodyHash: verify.ExtractSanitizerPayloadHash(p.RawClaims, "sanitized_fields_hash"),
			TMSManifestHash:         verify.ExtractSanitizerPayloadHash(p.RawClaims, "tms_manifest_hash"),
		})
		if err != nil {
			t.Fatal(err)
		}
		m["signable_protocol_version_emitted"] = float64(3)
		m["signable_v3_signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(k.witness.priv, v3b))
	}
	return m
}

// f16Tamper is the level-3 case: change what a claim says after signing (the
// sanitizer claim's entity count), leaving the witness-signed claim ids intact.
func f16Tamper(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	out := deepCopyMap(t, m)
	c := out["claims"].([]any)[1].(map[string]any)
	raw, _ := base64.StdEncoding.DecodeString(c["canonical_payload"].(string))
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["payload"].(map[string]any)["entities_found"] = float64(0)
	b, _ := json.Marshal(doc)
	c["canonical_payload"] = base64.StdEncoding.EncodeToString(b)
	return out
}

func f16Reason(t *testing.T, cert any, keys VerifyCertificateKeys) string {
	t.Helper()
	_, err := VerifyCertificate(cert, keys)
	if err == nil {
		return "valid"
	}
	var ce *CertificateError
	if !errors.As(err, &ce) {
		t.Fatalf("unexpected error type %T: %v", err, err)
	}
	return string(ce.Reason)
}

func f16Setup(t *testing.T) (f16Keys, VerifyCertificateKeys, VerifyCertificateKeys) {
	k := f16Keys{witness: f16NewPair(t), bridge: f16NewPair(t), sanitizer: f16NewPair(t)}
	only := VerifyCertificateKeys{WitnessKeyID: "witness_f16", WitnessPublicKey: k.witness.pub}
	with := only
	with.ServicePublicKeys = map[string]any{"dsa-bridge": k.bridge.pub, "dsa-sanitizer": k.sanitizer.pub}
	return k, only, with
}

func TestVerifyCertificate_ClaimSignatures_ChangedClaimNotValid(t *testing.T) {
	for _, v3 := range []bool{false, true} {
		name := map[bool]string{false: "v2", true: "v3"}[v3]
		t.Run(name, func(t *testing.T) {
			k, only, with := f16Setup(t)
			cert := f16Cert(t, k, v3)

			r, err := VerifyCertificate(cert, with)
			if err != nil {
				t.Fatalf("genuine cert: %v", err)
			}
			if r.SignableVersion != name || !r.ClaimSignaturesVerified {
				t.Fatalf("genuine cert: version %q claimsVerified %v", r.SignableVersion, r.ClaimSignaturesVerified)
			}

			tampered := f16Tamper(t, cert)
			// The witness signature alone still verifies (it covers only claim ids) ...
			r, err = VerifyCertificate(tampered, only)
			if err != nil || r.ClaimSignaturesVerified {
				t.Fatalf("witness-only on tampered: err %v claimsVerified %v", err, r != nil && r.ClaimSignaturesVerified)
			}
			// ... the claim-signature check catches the change.
			if got := f16Reason(t, tampered, with); got != string(ReasonInvalidSignature) {
				t.Fatalf("tampered claim with service keys: got %q, want invalid_signature", got)
			}
			strict := with
			strict.MinimumSignableVersion = "v3"
			if got := f16Reason(t, tampered, strict); got != string(ReasonInvalidSignature) {
				t.Fatalf("tampered claim, strict v3: got %q, want invalid_signature", got)
			}
		})
	}
}

func TestVerifyCertificate_ClaimSignatures_FailClosed(t *testing.T) {
	k, only, with := f16Setup(t)

	missing := only
	missing.ServicePublicKeys = map[string]any{"dsa-bridge": k.bridge.pub}
	if got := f16Reason(t, f16Cert(t, k, false), missing); got != string(ReasonInvalidSignature) {
		t.Errorf("service without key: got %q", got)
	}

	wrong := only
	wrong.ServicePublicKeys = map[string]any{"dsa-bridge": k.sanitizer.pub, "dsa-sanitizer": k.sanitizer.pub}
	if got := f16Reason(t, f16Cert(t, k, false), wrong); got != string(ReasonInvalidSignature) {
		t.Errorf("other service's key: got %q", got)
	}

	swapped := f16Cert(t, k, false)
	other := f16SignedClaim(t, k.sanitizer, "clm_other_cert", "dsa-sanitizer", "CLAIM_TYPE_PII_SANITIZED",
		map[string]any{"entities_found": float64(0)})
	c := swapped["claims"].([]any)[1].(map[string]any)
	c["canonical_payload"], c["signature"] = other["canonical_payload"], other["signature"]
	if got := f16Reason(t, swapped, with); got != string(ReasonInvalidSignature) {
		t.Errorf("payload naming another claim_id: got %q", got)
	}

	nonCanon := f16Cert(t, k, false)
	c0 := nonCanon["claims"].([]any)[0].(map[string]any)
	c0["signature"] = strings.TrimRight(c0["signature"].(string), "=")
	if got := f16Reason(t, nonCanon, with); got != string(ReasonInvalidSignature) {
		t.Errorf("non-canonical claim signature: got %q", got)
	}
}

// Review round 1, finding 1: with service keys, every OUTER claim field must
// agree with the signed canonical_payload (the chain verifier's step 7g
// rebuild, shared code). Each edit leaves every signature valid. The
// service_id case edits the bridge claim (the v3 witness signable reads the
// sanitizer hashes by service_id); its twin name carries the bridge key.
func TestVerifyCertificate_ClaimSignatures_OuterFieldsBound(t *testing.T) {
	edits := []struct {
		field string
		idx   int
		value any
	}{
		{"data_seen", 1, []any{"raw_prompt"}},
		{"data_not_seen", 1, []any{"pii_values"}},
		{"claim_type", 1, "CLAIM_TYPE_EVENTS_RECORDED"},
		{"request_id", 1, "req_f16_other"},
		{"timestamp", 1, "2026-11-21T09:00:00Z"},
		{"service_id", 0, "dsa-bridge-twin"},
	}
	for _, v3 := range []bool{false, true} {
		for _, e := range edits {
			name := map[bool]string{false: "v2", true: "v3"}[v3] + "/" + e.field
			t.Run(name, func(t *testing.T) {
				k, only, with := f16Setup(t)
				with.ServicePublicKeys["dsa-bridge-twin"] = k.bridge.pub
				cert := f16Cert(t, k, v3)
				cert["claims"].([]any)[e.idx].(map[string]any)[e.field] = e.value
				r, err := VerifyCertificate(cert, only)
				if err != nil || r.ClaimSignaturesVerified {
					t.Fatalf("witness-only: err %v", err)
				}
				if got := f16Reason(t, cert, with); got != string(ReasonInvalidSignature) {
					t.Fatalf("edited outer %s: got %q, want invalid_signature", e.field, got)
				}
			})
		}
	}
}

func TestVerifyCertificate_ClaimSignatures_TimestampComparedAsInstant(t *testing.T) {
	k, _, with := f16Setup(t)
	cert := f16Cert(t, k, false)
	cert["claims"].([]any)[1].(map[string]any)["timestamp"] = "2026-11-21T08:00:00.000Z"
	r, err := VerifyCertificate(cert, with)
	if err != nil || !r.ClaimSignaturesVerified {
		t.Fatalf("same instant in another textual form: err %v", err)
	}
}

func TestVerifyCertificate_ClaimSignatures_DuplicateClaimIDKeyRefused(t *testing.T) {
	k, _, with := f16Setup(t)
	cert := f16Cert(t, k, false)
	c := cert["claims"].([]any)[1].(map[string]any)
	raw, _ := base64.StdEncoding.DecodeString(c["canonical_payload"].(string))
	dup := []byte(strings.Replace(string(raw), `{"claim_id":`, `{"claim_id":"clm_other","claim_id":`, 1))
	c["canonical_payload"] = base64.StdEncoding.EncodeToString(dup)
	c["signature"] = base64.StdEncoding.EncodeToString(ed25519.Sign(k.sanitizer.priv, dup))
	if got := f16Reason(t, cert, with); got != string(ReasonInvalidSignature) {
		t.Fatalf("duplicate claim_id key: got %q, want invalid_signature", got)
	}
}
