package verify

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

// Parser and helper pins the three SDKs share (the corpus-wide grammar
// vectors live in parity_corpus_test.go).
func TestChain_CrossSDKRules(t *testing.T) {
	if _, err := DecodeDocument([]byte(strings.Repeat("[", 256) + strings.Repeat("]", 256))); err != nil {
		t.Errorf("depth 256: %v", err)
	}
	if _, err := DecodeDocument([]byte(strings.Repeat("[", 257) + strings.Repeat("]", 257))); err == nil {
		t.Error("depth 257 accepted")
	}
	if _, err := DecodeDocument([]byte(`["` + strings.Repeat("[", 300) + `"]`)); err != nil {
		t.Errorf("brackets inside a string counted: %v", err)
	}
	// An unpaired surrogate escape is refused, never replaced by U+FFFD.
	for _, in := range []string{`{"\udc00":1}`, `["\ud800x"]`, `["\ud800\ud800"]`} {
		if _, err := DecodeDocument([]byte(in)); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
	v, err := DecodeDocument([]byte(`{"a":"x😀"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := v.(map[string]any)["a"]; got != "x\U0001f600" {
		t.Errorf("surrogate pair: %q", got)
	}
	if chainQiVerdict(" pass ") != "QI_VERDICT_PASS" || chainQiVerdict("paß") != "QI_VERDICT_UNKNOWN" ||
		chainQiVerdict("\u001cPASS") != "QI_VERDICT_UNKNOWN" {
		t.Error("qi verdict trim / upper-casing")
	}
}

// Every corpus test key is refused without AllowTestKeys and loads with it.
func TestChain_TestKeysRefusedByDefault(t *testing.T) {
	if len(ChainTestKeys) != 10 {
		t.Fatalf("%d test keys", len(ChainTestKeys))
	}
	for _, k := range ChainTestKeys {
		if _, code := PinnedChainKey(k, false); code != KeyPolicyTestKey {
			t.Errorf("%s: %s", k, code)
		}
		if _, code := PinnedChainKey(k, true); code != KeyPolicyOK {
			t.Errorf("%s allowed: %s", k, code)
		}
	}
	for _, in := range []any{nil, 42, []byte{1, 2, 3}, ed25519.PublicKey(make([]byte, 31))} {
		if _, code := PinnedChainKey(in, true); code != KeyPolicyMalformed {
			t.Errorf("%v: %s", in, code)
		}
	}
}

// The strict signature rule refuses S + L, which crypto/ed25519 alone also
// refuses, and a small-order R, which crypto/ed25519 alone accepts.
func TestChain_StrictSignatureRule(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("synthetic message")
	sig := ed25519.Sign(priv, msg)
	if !chainStrictVerify(pub, msg, sig) {
		t.Fatal("honest signature refused")
	}
	// R = the identity (y = 1): small order.
	bad := append([]byte{}, sig...)
	copy(bad[:32], append([]byte{1}, make([]byte, 31)...))
	if chainStrictVerify(pub, msg, bad) {
		t.Error("small-order R accepted")
	}
	// R with y = p + 1 (non-canonical).
	copy(bad[:32], []byte{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f})
	if chainStrictVerify(pub, msg, bad) {
		t.Error("non-canonical R accepted")
	}
	if chainStrictVerify(pub, msg, sig[:63]) {
		t.Error("63-byte signature accepted")
	}
}

// Corpus v1.2.1: the two-signer label is not capped by step 8d itself (the
// EGRESS_UNATTESTED ceiling comes from the absent dsa-ai digests).
func TestChain_TwoSignerTierNotCapped(t *testing.T) {
	claims := []map[string]any{{"service_id": "dsa-sanitizer"}, {"service_id": "dsa-gateway"}}
	canon := []map[string]any{{}, {"cert_tier": "input-shield"}}
	tier, ok, capped := chainCertTier(claims, canon, ChainTierInputShieldTwoSigner, "VERDICT_VERIFIED")
	if tier != ChainTierInputShieldTwoSigner || !ok || capped {
		t.Errorf("got %q %v %v", tier, ok, capped)
	}
}
