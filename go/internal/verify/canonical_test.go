package verify

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func tsFixturesDir(t *testing.T) string {
	t.Helper()
	// go/internal/verify → go → monorepo root.
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// cwd is <sdks-repo>/go/internal/verify; the monorepo root is three up.
	root := filepath.Join(cwd, "..", "..", "..")
	fixtures := filepath.Join(root, "ts", "src", "verify-certificate", "__fixtures__")
	info, err := os.Stat(fixtures)
	if err != nil || !info.IsDir() {
		t.Fatalf("expected TS fixtures at %s: %v", fixtures, err)
	}
	return fixtures
}

// reviveRawIntegers mirrors the TS/Python reviver: {"$rawInt": N} → N.
// Go's int type is sufficient; no branded wrapper needed. Because the
// input JSON carries integers as objects (not numbers), Go's json.Unmarshal
// decodes them as map[string]any with a float64 value; we cast to int.
func reviveRawIntegers(v any) any {
	switch x := v.(type) {
	case []any:
		for i, item := range x {
			x[i] = reviveRawIntegers(item)
		}
		return x
	case map[string]any:
		if len(x) == 1 {
			if raw, ok := x["$rawInt"]; ok {
				if f, ok := raw.(float64); ok {
					return int(f)
				}
			}
		}
		for k, val := range x {
			x[k] = reviveRawIntegers(val)
		}
		return x
	default:
		return v
	}
}

func TestCanonicalJSON_SortsKeysAtTopLevel(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{"b": "x", "a": "y"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), `{"a":"y","b":"x"}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCanonicalJSON_SortsKeysRecursively(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{
		"z": map[string]any{"y": "b", "x": "a"},
		"a": "c",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), `{"a":"c","z":{"x":"a","y":"b"}}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCanonicalJSON_PreservesArrayOrder(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{"list": []any{"c", "a", "b"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), `{"list":["c","a","b"]}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCanonicalJSON_IntLeavesUnquoted(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{"n": 1, "s": "1"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(out), `{"n":1,"s":"1"}`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCanonicalJSON_RejectsFloats(t *testing.T) {
	_, err := CanonicalJSON(map[string]any{"n": 1.5})
	if err == nil {
		t.Fatal("expected error on float")
	}
	if !strings.Contains(err.Error(), "float") {
		t.Fatalf("error should mention 'float': %v", err)
	}
}

// M3 - witness parity. The witness signer emits <, >, & LITERALLY (it does NOT
// HTML-escape them); U+2028 / U+2029 are >= U+0080 so they escape to lowercase.
func TestCanonicalJSON_EmitsHTMLCharsLiterallyAndEscapesLineSeparators(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{"k": "<>&\u2028\u2029"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"k":"<>&\u2028\u2029"}`
	if got := string(out); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// M3 - every rune >= U+0080 escapes to lowercase \uXXXX; a supplementary-plane
// rune (emoji) becomes a UTF-16 surrogate pair, matching the witness's
// encodePythonAsciiString.
func TestCanonicalJSON_EscapesNonASCIIAndEmojiSurrogatePair(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{"k": "\u00e9\U0001F984"}) // e-acute + unicorn
	if err != nil {
		t.Fatal(err)
	}
	want := `{"k":"\u00e9\ud83e\udd84"}`
	if got := string(out); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// M3 - U+007F (DEL) is escaped to lowercase \u007f despite being ASCII.
func TestCanonicalJSON_EscapesDELChar(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{"k": "a\u007fb"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"k":"a\u007fb"}`
	if got := string(out); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCanonicalJSON_QuotesAndBackslashes(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{"k": "\"\\"})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"k":"\"\\"}`
	if got := string(out); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestCanonicalJSON_EmptyMapAndArray(t *testing.T) {
	out, err := CanonicalJSON(map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "{}" {
		t.Fatalf("got %q, want {}", string(out))
	}
	out, err = CanonicalJSON(map[string]any{"a": []any{}})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"a":[]}` {
		t.Fatalf("got %q, want {\"a\":[]}", string(out))
	}
}

func TestCanonicalJSON_RejectsBytes(t *testing.T) {
	_, err := CanonicalJSON(map[string]any{"a": []byte("payload")})
	if err == nil || !strings.Contains(err.Error(), "[]byte") {
		t.Fatalf("expected []byte rejection, got %v", err)
	}
}

func TestCanonicalJSON_RejectsUnsupportedTypes(t *testing.T) {
	_, err := CanonicalJSON(map[string]any{"a": struct{ X int }{1}})
	if err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected unsupported-type error, got %v", err)
	}
}

// Golden cross-check against the Go-assembler reference hex. Any byte
// divergence here means the Go SDK canonical disagrees with the server-
// side canonical, which produces invalid_signature on valid certs.
func TestCanonicalJSON_MatchesGoReferenceHex(t *testing.T) {
	fixtures := tsFixturesDir(t)

	inputBytes, err := os.ReadFile(filepath.Join(fixtures, "canonical-json-go-reference-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw any
	if err := json.Unmarshal(inputBytes, &raw); err != nil {
		t.Fatal(err)
	}
	revived := reviveRawIntegers(raw)

	hexBytes, err := os.ReadFile(filepath.Join(fixtures, "canonical-json-go-reference.hex"))
	if err != nil {
		t.Fatal(err)
	}
	expectedHex := strings.TrimSpace(string(hexBytes))

	out, err := CanonicalJSON(revived)
	if err != nil {
		t.Fatal(err)
	}
	actualHex := hex.EncodeToString(out)
	if actualHex != expectedHex {
		t.Fatalf("canonical-JSON byte-equality failed:\n  got:  %s\n  want: %s\n  got-bytes:  %s\n  want-bytes: %s",
			actualHex, expectedHex, string(out), "<see hex>")
	}
}

// M3 - cross-language NON-ASCII golden cross-check. The hex bytes are the raw
// output of the witness signer (dual-sandbox-architecture/pkg/veil/canonical.go,
// CanonicalJSON) on the same input - the authoritative faithfulness assertion
// for the non-ASCII path: every codepoint >= U+0080 -> lowercase \uXXXX
// (supplementary plane -> surrogate pair); <>& literal; U+2028/2029 escaped;
// control chars; non-ASCII KEYS sorted bytewise over UTF-8; nested + array-of-
// maps. A one-byte divergence here means a non-ASCII signable would fail
// signature verification on a valid cert. The SAME fixture is also consumed by
// the TS and Python golden tests.
func TestCanonicalJSON_MatchesWitnessReferenceHex_NonASCII(t *testing.T) {
	fixtures := tsFixturesDir(t)

	inputBytes, err := os.ReadFile(filepath.Join(fixtures, "canonical-json-nonascii-go-reference-input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw any
	if err := json.Unmarshal(inputBytes, &raw); err != nil {
		t.Fatal(err)
	}
	revived := reviveRawIntegers(raw)

	hexBytes, err := os.ReadFile(filepath.Join(fixtures, "canonical-json-nonascii-go-reference.hex"))
	if err != nil {
		t.Fatal(err)
	}
	expectedHex := strings.TrimSpace(string(hexBytes))

	out, err := CanonicalJSON(revived)
	if err != nil {
		t.Fatal(err)
	}
	actualHex := hex.EncodeToString(out)
	if actualHex != expectedHex {
		t.Fatalf("non-ASCII canonical byte-equality failed:\n  got:  %s\n  want: %s\n  got-str: %s",
			actualHex, expectedHex, string(out))
	}
}

// TOB-001 — Signable freeze test. The 7-key witness signable map is a
// hard-locked W2A invariant: any change to its shape, key order
// (canonical-JSON sorts alphabetically so this is automatic), or per-field
// encoding breaks every external verifier in the wild. Locking the canonical
// bytes against a Go-reference hex fixture catches regressions at the
// byte-identity layer rather than at the higher signature-verification layer.
//
// The hex was produced by running DeriveSignedBytes over the field values
// from `cert-go-signed-reference.json` (which is itself produced by the Go
// assembler oracle — see verify_certificate_test.go:79-99) and is the
// authoritative pinned canonical form. If this test fails after a deliberate
// signable-shape change, regenerate BOTH the Go-side and SDK-side fixtures
// per the steps documented at
//
//	dual-sandbox-architecture/services/veil-witness/internal/testoracle/README.md
//
// — never paper over by regenerating just this hex.
func TestDeriveSignedBytes_MatchesSignableFreezeHex(t *testing.T) {
	fixtures := tsFixturesDir(t)

	hexBytes, err := os.ReadFile(filepath.Join(fixtures, "signable-go-reference.hex"))
	if err != nil {
		t.Fatal(err)
	}
	expectedHex := strings.TrimSpace(string(hexBytes))

	// Field values match cert-go-signed-reference.json. Hard-coded here
	// rather than parsed from the fixture because (a) DeriveSignedBytes is
	// in package `verify` (internal) and the cert-parsing helper isn't in
	// scope without an import cycle, and (b) hard-coding makes the freeze
	// boundary explicit — any change to either the cert fixture or the
	// expected bytes must be reflected here.
	out, err := DeriveSignedBytes(DeriveSignedBytesInput{
		CertificateID: "veil_oracle_0000000000000001",
		RequestID:     "req_oracle_0000000000000001",
		ClaimRequestIDs: []string{
			"req_oracle_0000000000000001",
			"req_oracle_0000000000000001",
			"req_oracle_0000000000000001",
			"req_oracle_0000000000000001",
		},
		ClaimIDs: []string{
			"clm_oracle_dsa-bridge",
			"clm_oracle_dsa-sanitizer",
			"clm_oracle_dsa-ai",
			"clm_oracle_dsa-audit",
		},
		IssuedAt:               "2026-04-20T05:24:12.710321721Z",
		OverallVerdictFullName: "VERDICT_VERIFIED",
		WitnessKeyID:           "witness_v1",
	})
	if err != nil {
		t.Fatalf("DeriveSignedBytes returned error: %v", err)
	}
	actualHex := hex.EncodeToString(out)
	if actualHex != expectedHex {
		t.Fatalf("signable byte-equality failed (W2A invariant violated):\n  got:  %s\n  want: %s\n  got-bytes: %s",
			actualHex, expectedHex, string(out))
	}
}

// Companion structural assertion to the byte-identity test above. Easier
// failure-message readability if a future contributor adds a key, while the
// hex equality remains the load-bearing freeze.
func TestDeriveSignedBytes_SignableContainsExactlySevenKeys(t *testing.T) {
	out, err := DeriveSignedBytes(DeriveSignedBytesInput{
		CertificateID:          "veil_oracle_0000000000000001",
		RequestID:              "req_oracle_0000000000000001",
		ClaimRequestIDs:        []string{"req_oracle_0000000000000001"},
		ClaimIDs:               []string{"clm_oracle_dsa-bridge"},
		IssuedAt:               "2026-04-20T05:24:12.710321721Z",
		OverallVerdictFullName: "VERDICT_VERIFIED",
		WitnessKeyID:           "witness_v1",
	})
	if err != nil {
		t.Fatalf("DeriveSignedBytes returned error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("signable bytes are not valid JSON: %v", err)
	}
	wantKeys := []string{
		"certificate_id", "claim_ids", "issued_at", "overall_verdict",
		"protocol_version", "request_id", "witness_key_id",
	}
	if len(decoded) != len(wantKeys) {
		t.Fatalf("signable has %d keys, want %d (W2A 7-key invariant)", len(decoded), len(wantKeys))
	}
	for _, k := range wantKeys {
		if _, ok := decoded[k]; !ok {
			t.Errorf("signable missing required key %q", k)
		}
	}
	// byok_exempt MUST NOT leak into the signable — tamper-evidence is
	// INDIRECT via the bridge claim's bridge-signed canonical_payload.
	if _, leaked := decoded["byok_exempt"]; leaked {
		t.Errorf("byok_exempt leaked into signable map (W2A invariant violated)")
	}
	if _, leaked := decoded["client_id"]; leaked {
		t.Errorf("client_id leaked into signable map (W2A invariant violated)")
	}
}
