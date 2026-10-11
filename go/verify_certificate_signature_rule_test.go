package lucairn

import (
	"encoding/json"
	"testing"
)

// The corpus case tamper_witness_signature_small_order_r (both witness
// signatures made with nonce 0, so R is the identity) through the
// witness-only VerifyCertificate: refused as an invalid signature by the
// SDK's own rule. crypto/ed25519 by itself accepts that signature.
func TestVerifyCertificate_CorpusSmallOrderRRefused(t *testing.T) {
	_, chainKeys := parityLoad(t)
	keys := VerifyCertificateKeys{WitnessKeyID: chainKeys.WitnessKeyID, WitnessPublicKey: chainKeys.WitnessPublicKey}

	// Control: the honest certificate the case was built from verifies.
	honest, err := VerifyCertificate(parityLoadCase(t, "cases/honest_full_chain_egress.json").input(t), keys)
	if err != nil {
		t.Fatalf("honest corpus certificate refused: %v", err)
	}
	if honest.OverallVerdict != "VERDICT_VERIFIED" || honest.SignableVersion != "v3" {
		t.Fatalf("honest corpus certificate: %q %q", honest.OverallVerdict, honest.SignableVersion)
	}

	c := parityLoadCase(t, "cases/tamper_witness_signature_small_order_r.json")
	var want paritySummary
	if err := json.Unmarshal(c.Expected["default"], &want); err != nil {
		t.Fatal(err)
	}
	if want.Verdict != "FAILED" || want.Reason != "witness_signature_invalid" {
		t.Fatalf("corpus expectation changed: %+v", want)
	}
	for _, mv := range []string{"", "v3"} {
		k := keys
		k.MinimumSignableVersion = mv
		got, err := VerifyCertificate(c.input(t), k)
		if err == nil {
			t.Fatalf("policy %q: small-order R accepted: %+v", mv, *got)
		}
		assertReason(t, err, ReasonInvalidSignature)
	}
}
