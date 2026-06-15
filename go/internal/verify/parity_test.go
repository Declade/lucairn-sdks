package verify

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// CROSS-LANGUAGE SIGNABLE-RECONSTRUCTION PARITY (2026-06-15)
//
// These tests lock the Go signable reconstruction against a SHARED golden hex
// that lives BYTE-IDENTICALLY in all three SDK fixture directories:
//
//   go/internal/verify/testdata/real-v{2,3}-signable-go-reference.hex
//   ts/src/verify-certificate/__fixtures__/real-v{2,3}-signable-go-reference.hex
//   python/tests/fixtures/real-v{2,3}-signable-go-reference.hex
//
// The hex is the canonical signable bytes derived from the SHARED real cert
// fixture (real-v3-cert.fixture.json, also byte-identical across all three
// dirs). Each language asserts it reproduces this exact hex. Because the same
// hex is pinned in every language's tree, byte-identity in each language is a
// transitive proof of cross-language byte-equivalence.
//
// HARD GATE: these bytes are UNCHANGED from origin/main — the signable
// reconstruction parity fixes (TS flat-fallback, TS+Python issued_at UTC
// normalization, TS bytewise-UTF-8 key sort) are byte-equivalent on every real
// cert (which only ever carries the wrapped canonical_payload shape and Zulu
// timestamps with ASCII keys). If this test fails, the reconstruction drifted —
// fix the reconstruction, do NOT regenerate the hex.
// ---------------------------------------------------------------------------

func readSharedHex(t *testing.T, name string) string {
	t.Helper()
	cwd, _ := os.Getwd()
	data, err := os.ReadFile(filepath.Join(cwd, "testdata", name))
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return strings.TrimSpace(string(data))
}

func parseRealV3Fixture(t *testing.T) *RawCert {
	t.Helper()
	certData := loadV3Fixture(t, "real-v3-cert.fixture.json")
	var raw any
	if err := json.Unmarshal(certData, &raw); err != nil {
		t.Fatalf("parse real-v3-cert.fixture.json: %v", err)
	}
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse(real-v3-cert): %v", err)
	}
	return parsed
}

func TestParity_RealCert_V2SignableMatchesSharedGoldenHex(t *testing.T) {
	parsed := parseRealV3Fixture(t)
	out, err := DeriveSignedBytes(DeriveSignedBytesInput{
		CertificateID:          parsed.CertificateID,
		RequestID:              parsed.RequestID,
		ClaimRequestIDs:        parsed.ClaimRequestIDs,
		ClaimIDs:               parsed.ClaimIDs,
		IssuedAt:               parsed.IssuedAt,
		OverallVerdictFullName: parsed.OverallVerdict,
		WitnessKeyID:           parsed.WitnessKeyID,
	})
	if err != nil {
		t.Fatalf("DeriveSignedBytes: %v", err)
	}
	got := hex.EncodeToString(out)
	want := readSharedHex(t, "real-v2-signable-go-reference.hex")
	if got != want {
		t.Fatalf("v2 signable drifted from the shared cross-language golden hex:\n"+
			"  got:  %s\n  want: %s\n  got-json: %s", got, want, string(out))
	}
}

func TestParity_RealCert_V3SignableMatchesSharedGoldenHex(t *testing.T) {
	parsed := parseRealV3Fixture(t)
	out, err := DeriveV3SignedBytes(DeriveV3SignedBytesInput{
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
	if err != nil {
		t.Fatalf("DeriveV3SignedBytes: %v", err)
	}
	got := hex.EncodeToString(out)
	want := readSharedHex(t, "real-v3-signable-go-reference.hex")
	if got != want {
		t.Fatalf("v3 signable drifted from the shared cross-language golden hex:\n"+
			"  got:  %s\n  want: %s\n  got-json: %s", got, want, string(out))
	}
}

// ---------------------------------------------------------------------------
// PARITY SHAPE TESTS — the previously-divergent shapes (Go reference behaviour)
//
// Go was already correct on every one of these (it is the reference). The TS
// and Python ports were brought up to match it. These tests pin the Go
// reference outputs so the TS/Python parity tests have an authoritative target.
// ---------------------------------------------------------------------------

// FLAT canonical_payload: the hash fields can live at the top level of the
// canonical_payload (no "payload" wrapper). Go reads them via the flat
// fallback in ExtractSanitizerPayloadHash; TS previously returned null.
func TestParity_FlatCanonicalPayload_HashRead(t *testing.T) {
	flatCP := `{"redaction_manifest_hash":"abc123"}`
	cpB64 := base64StdEncode(flatCP)
	rawClaims := []any{
		map[string]any{
			"service_id":        "dsa-sanitizer",
			"canonical_payload": cpB64,
		},
	}
	got := ExtractSanitizerPayloadHash(rawClaims, "redaction_manifest_hash")
	if got == nil || *got != "abc123" {
		t.Fatalf("flat-fallback hash read: got %v, want abc123", got)
	}
}

// WRAPPED canonical_payload: the normal shape (hash under "payload"). Both flat
// and wrapped must read identically.
func TestParity_WrappedCanonicalPayload_HashRead(t *testing.T) {
	wrappedCP := `{"payload":{"redaction_manifest_hash":"abc123"}}`
	cpB64 := base64StdEncode(wrappedCP)
	rawClaims := []any{
		map[string]any{
			"service_id":        "dsa-sanitizer",
			"canonical_payload": cpB64,
		},
	}
	got := ExtractSanitizerPayloadHash(rawClaims, "redaction_manifest_hash")
	if got == nil || *got != "abc123" {
		t.Fatalf("wrapped hash read: got %v, want abc123", got)
	}
}

// OFFSET timestamp: a non-Zulu offset normalizes to the equivalent UTC Z time
// (and trailing zeros stripped). Go reference behaviour the ports must match.
func TestParity_OffsetTimestamp_NormalizedToUTC(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026-05-01T14:00:00.100000000+02:00", "2026-05-01T12:00:00.1Z"},
		{"2026-05-01T08:00:00-03:00", "2026-05-01T11:00:00Z"},
		{"2026-06-10T00:01:59.100000000+00:00", "2026-06-10T00:01:59.1Z"},
		{"2026-06-10T00:01:59.878143387Z", "2026-06-10T00:01:59.878143387Z"},
		{"2026-06-10T00:01:59.000000000Z", "2026-06-10T00:01:59Z"},
		{"2026-06-10T00:01:59Z", "2026-06-10T00:01:59Z"},
		{"not-a-timestamp", "not-a-timestamp"}, // fail-open
	}
	for _, c := range cases {
		if got := normalizeIssuedAt(c.in); got != c.want {
			t.Errorf("normalizeIssuedAt(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// NON-ASCII key: canonical JSON sorts map keys by UTF-8 bytes. Go's
// encoding/json already does this; the TS port switched from a UTF-16 sort to
// a bytewise-UTF-8 sort to match.
//
// Two keys whose UTF-16 vs UTF-8 sort orders are OPPOSITE:
//
//	bmpKey    = U+E000 (private-use, in the BMP) -> UTF-8 ee 80 80
//	astralKey = U+1F600 (grinning face emoji)    -> UTF-8 f0 9f 98 80
//
// UTF-16: astralKey's leading surrogate 0xD83D < 0xE000, so astralKey would
// sort BEFORE bmpKey (the naive JS Array.prototype.sort order). UTF-8: 0xee <
// 0xf0, so bmpKey sorts BEFORE astralKey. This test pins the Go (UTF-8)
// reference so the TS/Python ports have an authoritative target.
func TestParity_NonAsciiKeySort(t *testing.T) {
	const bmpKey = "\uE000"
	const astralKey = "\U0001F600"
	m := map[string]any{
		bmpKey:    "bmp",
		astralKey: "astral",
		"a":       "ascii",
	}
	out, err := CanonicalJSON(m)
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	// UTF-8 byte order: "a" (0x61) < bmpKey (0xee...) < astralKey (0xf0...).
	want := `{"a":"ascii","` + bmpKey + `":"bmp","` + astralKey + `":"astral"}`
	if string(out) != want {
		t.Fatalf("non-ASCII key sort:\n  got:  %s\n  want: %s", string(out), want)
	}
}

// base64StdEncode is a tiny helper local to this test file.
func base64StdEncode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
