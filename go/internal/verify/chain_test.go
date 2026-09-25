package verify

import (
	"strings"
	"testing"
)

// Rules the three SDKs pin identically where the parity corpus is silent
// (the TS and Python SDKs carry the same vectors).
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
	v, err := DecodeDocument([]byte(`{"\udc00":"\ud800x\ud83d\ude00"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := v.(map[string]any)["\ufffd"]; got != "\ufffdx\U0001f600" {
		t.Errorf("surrogates: %q", got)
	}
	if chainQiVerdict(" pass\n") != "QI_VERDICT_PASS" || chainQiVerdict("pa\u00df") != "QI_VERDICT_UNKNOWN" {
		t.Error("qi verdict upper-casing")
	}
}
