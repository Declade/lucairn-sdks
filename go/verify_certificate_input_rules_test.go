package lucairn

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/declade/lucairn-sdks/go/internal/verify"
)

// Input rules of the witness-only VerifyCertificate that all three SDKs
// share (the parity corpus is the reference):
//   - ONE whitespace set (unicode.IsSpace) for every blank / present test;
//   - a signature text is canonical standard padded base64, else
//     ReasonInvalidSignature;
//   - with raw-bytes input, protocol_version and
//     signable_protocol_version_emitted are integer TOKENS in [0, 2^64-1],
//     else ReasonMalformed. Map / struct input is judged by value.

func inputRuleKeys(t *testing.T) VerifyCertificateKeys {
	t.Helper()
	_, chainKeys := parityLoad(t)
	return VerifyCertificateKeys{WitnessKeyID: chainKeys.WitnessKeyID, WitnessPublicKey: chainKeys.WitnessPublicKey}
}

// inputRuleCert returns a corpus certificate as a map.
func inputRuleCert(t *testing.T, id string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(parityLoadCase(t, "cases/"+id+".json").input(t), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// inputRuleOutcome is "ACCEPT:<signable version>" or the refusal reason.
func inputRuleOutcome(t *testing.T, cert any, keys VerifyCertificateKeys) string {
	t.Helper()
	res, err := VerifyCertificate(cert, keys)
	if err == nil {
		return "ACCEPT:" + res.SignableVersion
	}
	var ce *CertificateError
	if !errors.As(err, &ce) {
		t.Fatalf("want *CertificateError, got %T (%v)", err, err)
	}
	return string(ce.Reason)
}

// inputRuleWith returns the certificate as a map and as raw bytes, with one
// top-level field replaced.
func inputRuleWith(t *testing.T, id, field string, value any) (map[string]any, []byte) {
	t.Helper()
	m := inputRuleCert(t, id)
	m[field] = value
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return m, b
}

func TestVerifyCertificate_OneWhitespaceSet(t *testing.T) {
	keys := inputRuleKeys(t)
	if got := inputRuleOutcome(t, inputRuleCert(t, "honest_full_chain_egress"), keys); got != "ACCEPT:v3" {
		t.Fatalf("v3 control: %s", got)
	}
	if got := inputRuleOutcome(t, inputRuleCert(t, "legacy_v2_signable_only"), keys); got != "ACCEPT:v2" {
		t.Fatalf("v2 control: %s", got)
	}
	// The corpus case: signable_v3_signature = U+001C on a legacy v2 certificate.
	c := parityLoadCase(t, "cases/tamper_signable_v3_signature_control_char.json")
	if got := inputRuleOutcome(t, c.input(t), keys); got != string(ReasonVersionDowngradeDetected) {
		t.Errorf("corpus control-char case: %s", got)
	}
	for _, tc := range []struct {
		name  string
		ch    string
		blank bool
	}{
		{"U+001C", "\u001c", false}, {"U+001F", "\u001f", false}, {"U+0085", "\u0085", true},
		{"U+FEFF", string(rune(0xFEFF)), false}, {"U+00A0", "\u00a0", true}, {"U+2028", "\u2028", true},
		{"U+200B", "\u200b", false}, {"space", " ", true},
	} {
		pick := func(blank, present string) string {
			if tc.blank {
				return blank
			}
			return present
		}
		for _, check := range []struct{ id, field, want string }{
			{"legacy_v2_signable_only", "signable_v3_signature", pick("ACCEPT:v2", "version_downgrade_detected")},
			{"honest_full_chain_egress", "signable_v3_signature", pick("version_downgrade_detected", "invalid_signature")},
			{"legacy_v2_signable_only", "witness_signature", pick("witness_signature_missing", "invalid_signature")},
		} {
			m, raw := inputRuleWith(t, check.id, check.field, tc.ch)
			if got := inputRuleOutcome(t, m, keys); got != check.want {
				t.Errorf("%s in %s of %s (map): %s, want %s", tc.name, check.field, check.id, got, check.want)
			}
			if got := inputRuleOutcome(t, raw, keys); got != check.want {
				t.Errorf("%s in %s of %s (bytes): %s, want %s", tc.name, check.field, check.id, got, check.want)
			}
		}
	}
	// The simple check and the chain verifier trim the same set.
	for r := rune(0); r < 0x3100; r++ {
		s := string(r)
		if (strings.TrimSpace(s) == "") != (verify.ChainTrimSpace(s) == "") {
			t.Errorf("U+%04X: ChainTrimSpace and unicode.IsSpace disagree", r)
		}
	}
}

func TestVerifyCertificate_SignatureTextIsCanonicalBase64(t *testing.T) {
	keys := inputRuleKeys(t)
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	variants := func(s string) map[string]string {
		i := strings.IndexByte(alphabet, s[len(s)-3])
		if i%16 != 0 {
			t.Fatalf("expected zero padding bits in %q", s)
		}
		return map[string]string{
			"unpadded":                  strings.TrimRight(s, "="),
			"one pad character removed": s[:len(s)-1],
			"URL-safe alphabet":         strings.NewReplacer("+", "-", "/", "_").Replace(s),
			"embedded space":            s[:40] + " " + s[40:],
			"embedded LF":               s[:40] + "\n" + s[40:],
			"embedded CR":               s[:40] + "\r" + s[40:],
			"leading space":             " " + s,
			"trailing space":            s + " ",
			"trailing LF":               s + "\n",
			"non-zero padding bits":     s[:len(s)-3] + string(alphabet[i+1]) + "==",
			"trailing '!'":              s + "!",
			"trailing 'AAAA'":           s + "AAAA",
			"trailing '===='":           s + "====",
			"embedded '!'":              s[:40] + "!" + s[40:],
		}
	}
	for _, path := range []struct{ id, field string }{
		{"honest_full_chain_egress", "signable_v3_signature"},
		{"legacy_v2_signable_only", "witness_signature"},
	} {
		sig, _ := inputRuleCert(t, path.id)[path.field].(string)
		if !strings.ContainsAny(sig, "+/") {
			t.Fatalf("%s: signature has no + or /", path.id)
		}
		for name, text := range variants(sig) {
			if text == sig {
				t.Fatalf("%s: variant %q equals the signature", path.field, name)
			}
			m, raw := inputRuleWith(t, path.id, path.field, text)
			if got := inputRuleOutcome(t, m, keys); got != string(ReasonInvalidSignature) {
				t.Errorf("%s %s (map): %s", path.field, name, got)
			}
			if got := inputRuleOutcome(t, raw, keys); got != string(ReasonInvalidSignature) {
				t.Errorf("%s %s (bytes): %s", path.field, name, got)
			}
		}
	}
}

// inputRuleToken renders a corpus certificate with one top-level field
// written as the literal JSON token.
func inputRuleToken(t *testing.T, id, field, token string) []byte {
	t.Helper()
	const mark = "\x00TOKEN\x00"
	_, raw := inputRuleWith(t, id, field, mark)
	quoted, _ := json.Marshal(mark)
	if strings.Count(string(raw), string(quoted)) != 1 {
		t.Fatal("marker not found exactly once")
	}
	return []byte(strings.Replace(string(raw), string(quoted), token, 1))
}

func TestVerifyCertificate_IntegerTokensOnRawBytes(t *testing.T) {
	keys := inputRuleKeys(t)
	// The two corpus cases.
	for _, id := range []string{"tamper_protocol_version_float_token", "tamper_protocol_version_oversized_integer"} {
		c := parityLoadCase(t, "cases/"+id+".json")
		var want paritySummary
		if err := json.Unmarshal(c.Expected["default"], &want); err != nil || want.Reason != "malformed" {
			t.Fatalf("%s: corpus expectation %+v %v", id, want, err)
		}
		if got := inputRuleOutcome(t, c.input(t), keys); got != string(ReasonMalformed) {
			t.Errorf("%s (bytes): %s, want malformed", id, got)
		}
		if got := inputRuleOutcome(t, json.RawMessage(c.input(t)), keys); got != string(ReasonMalformed) {
			t.Errorf("%s (json.RawMessage): %s, want malformed", id, got)
		}
	}
	// protocol_version tokens.
	for token, want := range map[string]string{
		"2": "ACCEPT:v3", "3": "unsupported_protocol_version", "0": "unsupported_protocol_version",
		"2.0": "malformed", "2e0": "malformed", "20e-1": "malformed", "2.0000000000000001": "malformed",
		"2.5": "malformed", "-1": "malformed", "-2": "malformed", "1e400": "malformed",
		"18446744073709551616": "malformed", "100000000000000000000": "malformed",
		`"2"`: "malformed", "true": "malformed", "null": "malformed",
	} {
		if got := inputRuleOutcome(t, inputRuleToken(t, "honest_full_chain_egress", "protocol_version", token), keys); got != want {
			t.Errorf("protocol_version %s (bytes): %s, want %s", token, got, want)
		}
	}
	// signable_protocol_version_emitted tokens, on a v3 and on a legacy v2 certificate.
	for token, want := range map[string][2]string{
		"3":                    {"ACCEPT:v3", "version_downgrade_detected"},
		"2":                    {"version_downgrade_detected", "ACCEPT:v2"},
		"18446744073709551615": {"ACCEPT:v3", "version_downgrade_detected"},
		"3.0":                  {"malformed", "malformed"},
		"2.5":                  {"malformed", "malformed"},
		"3e0":                  {"malformed", "malformed"},
		"-1":                   {"malformed", "malformed"},
		"18446744073709551616": {"malformed", "malformed"},
		"1e400":                {"malformed", "malformed"},
		"null":                 {"version_downgrade_detected", "ACCEPT:v2"},
	} {
		for i, id := range []string{"honest_full_chain_egress", "legacy_v2_signable_only"} {
			if got := inputRuleOutcome(t, inputRuleToken(t, id, "signable_protocol_version_emitted", token), keys); got != want[i] {
				t.Errorf("signable_protocol_version_emitted %s on %s (bytes): %s, want %s", token, id, got, want[i])
			}
		}
	}
}

// Map and *VeilCertificate input carry no tokens: they are judged by value,
// exactly as before. float64(2) is the protocol version 2 whatever text it
// came from.
func TestVerifyCertificate_ParsedInputIsJudgedByValue(t *testing.T) {
	keys := inputRuleKeys(t)
	c := parityLoadCase(t, "cases/tamper_protocol_version_float_token.json")
	var m map[string]any
	if err := json.Unmarshal(c.input(t), &m); err != nil {
		t.Fatal(err)
	}
	if pv, _ := m["protocol_version"].(float64); pv != 2 {
		t.Fatalf("protocol_version decoded to %v", m["protocol_version"])
	}
	if got := inputRuleOutcome(t, m, keys); got != "ACCEPT:v3" {
		t.Errorf("float-token case as a map: %s", got)
	}
	var typed VeilCertificate
	if err := json.Unmarshal(parityLoadCase(t, "cases/honest_full_chain_egress.json").input(t), &typed); err != nil {
		t.Fatal(err)
	}
	if got := inputRuleOutcome(t, &typed, keys); got != "ACCEPT:v3" {
		t.Errorf("honest certificate as *VeilCertificate: %s", got)
	}
	// The same signable bytes as the untampered parent.
	parent, err := verify.Run(inputRuleCert(t, "honest_full_chain_egress"), keys.WitnessKeyID, keys.WitnessPublicKey, verify.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	tampered, err := verify.Run(m, keys.WitnessKeyID, keys.WitnessPublicKey, verify.RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if string(parent.SignedBytes) != string(tampered.SignedBytes) || len(parent.SignedBytes) == 0 {
		t.Error("signable bytes differ from the untampered parent")
	}
}
