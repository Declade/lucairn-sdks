package lucairn

// Optional, UNSIGNED verification.cert_tier on the type. Types
// only: the field decodes when present, absent or unknown (never an error),
// and the offline verifier's outcome does not depend on it, because neither
// witness signable carries it.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func certTierFixture(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("internal", "verify", "testdata", "real-v3-cert.fixture.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return m
}

func withCertTier(t *testing.T, tier *string) []byte {
	t.Helper()
	m := certTierFixture(t)
	v := m["verification"].(map[string]any)
	if tier == nil {
		delete(v, "cert_tier")
	} else {
		v["cert_tier"] = *tier
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return out
}

func TestVeilVerificationResult_CertTier_OptionalAndVerbatim(t *testing.T) {
	tiers := []*string{nil}
	for _, s := range []string{"full_chain", "input_shield", "input_shield_two_signer", "", "input-shield", "some_future_tier"} {
		s := s
		tiers = append(tiers, &s)
	}
	for _, tier := range tiers {
		var cert VeilCertificate
		if err := json.Unmarshal(withCertTier(t, tier), &cert); err != nil {
			t.Fatalf("tier %v: decode error: %v", tier, err)
		}
		want := ""
		if tier != nil {
			want = *tier
		}
		if cert.Verification.CertTier != want {
			t.Fatalf("tier %v: got %q want %q", tier, cert.Verification.CertTier, want)
		}
	}
}

func TestVerifyCertificate_OutcomeDoesNotDependOnCertTier(t *testing.T) {
	keys := productionKeysForCertTier(t)
	var baseline *VerifyCertificateResult
	for _, s := range []string{"", "full_chain", "input_shield", "some_future_tier"} {
		s := s
		var tier *string
		if s != "" {
			tier = &s
		}
		res, err := VerifyCertificate(withCertTier(t, tier), keys)
		if err != nil {
			t.Fatalf("tier %q: verify failed: %v", s, err)
		}
		if baseline == nil {
			baseline = res
			continue
		}
		if res.SignableVersion != baseline.SignableVersion || res.OverallVerdict != baseline.OverallVerdict {
			t.Fatalf("tier %q changed the result: %+v vs %+v", s, res, baseline)
		}
	}
}

func productionKeysForCertTier(t *testing.T) VerifyCertificateKeys {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("internal", "verify", "testdata", "production-witness-pubkey.json"))
	if err != nil {
		t.Fatalf("read pubkey: %v", err)
	}
	var k struct {
		WitnessKeyID string `json:"witnessKeyID"`
		PublicKey    string `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	return VerifyCertificateKeys{WitnessKeyID: k.WitnessKeyID, WitnessPublicKey: k.PublicKey}
}
