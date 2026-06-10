package verify

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadV3Fixture loads a named fixture from the testdata/ directory next to
// this test file.
func loadV3Fixture(t *testing.T, name string) []byte {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// cwd = <sdks-repo>/go/internal/verify
	path := filepath.Join(cwd, "testdata", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return data
}

// loadProductionWitnessPublicKey returns the production Ed25519 public key
// (base64-encoded) and key ID from the production-witness-pubkey.json fixture.
func loadProductionWitnessPublicKey(t *testing.T) (keyID string, pubKeyBase64 string) {
	t.Helper()
	data := loadV3Fixture(t, "production-witness-pubkey.json")
	var kf struct {
		WitnessKeyID string `json:"witnessKeyID"`
		PublicKey    string `json:"publicKey"`
	}
	if err := json.Unmarshal(data, &kf); err != nil {
		t.Fatalf("parse production-witness-pubkey.json: %v", err)
	}
	if kf.WitnessKeyID == "" || kf.PublicKey == "" {
		t.Fatalf("production-witness-pubkey.json missing required fields")
	}
	return kf.WitnessKeyID, kf.PublicKey
}

// --- Test (a): real v3 cert round-trip — ANTI-GAMING guard ---
//
// This test is the primary acceptance gate (PRD criterion #7).
// It verifies the real production v3 cert using the production witness
// Ed25519 public key. A valid result requires byte-exact reconstruction of
// the 13-key v3 signable map — any deviation produces an invalid Ed25519
// signature, which surfaces as verify.Run returning ReasonInvalidSignature.
//
// DO NOT weaken this test. If it fails, fix the reconstruction, not the test.

func TestDeriveV3SignedBytes_RealProductionCert_RoundTrip(t *testing.T) {
	// Load real production v3 cert (16.7KB, both v2 + v3 signatures,
	// signable_protocol_version_emitted: 3, witness-signed on production
	// Hetzner pilot, manifest stripped by gateway server-side pipeline).
	certData := loadV3Fixture(t, "real-v3-cert.fixture.json")
	var rawCert any
	if err := json.Unmarshal(certData, &rawCert); err != nil {
		t.Fatalf("parse real-v3-cert.fixture.json: %v", err)
	}
	certMap := rawCert.(map[string]any)

	// Sanity-check the fixture carries the expected protocol version.
	pve := certMap["signable_protocol_version_emitted"]
	if pve == nil {
		t.Fatalf("fixture missing signable_protocol_version_emitted — fixture may be a v2 cert")
	}

	// Production witness public key.
	keyID, pubBase64 := loadProductionWitnessPublicKey(t)
	pubBytes, err := base64.StdEncoding.DecodeString(pubBase64)
	if err != nil {
		t.Fatalf("decode production public key: %v", err)
	}
	if len(pubBytes) != 32 {
		t.Fatalf("production public key must be 32 bytes, got %d", len(pubBytes))
	}

	// Run the full verify pipeline.
	result, runErr := Run(rawCert, keyID, pubBytes)
	if runErr != nil {
		t.Fatalf("Run failed on real production v3 cert: %v\n"+
			"This means the v3 signable reconstruction is NOT byte-exact.\n"+
			"Fix the reconstruction in v3_signable.go — do NOT weaken this test.",
			runErr)
	}

	// --- Assertion (a): valid=true + SignableVersion="v3" ---
	if result.SignableVersion != "v3" {
		t.Errorf("SignableVersion = %q, want %q (PRD criterion #7)", result.SignableVersion, "v3")
	}
	if result.CertificateID != certMap["certificate_id"].(string) {
		t.Errorf("CertificateID = %q, want %q", result.CertificateID, certMap["certificate_id"].(string))
	}
	if result.WitnessKeyID != keyID {
		t.Errorf("WitnessKeyID = %q, want %q", result.WitnessKeyID, keyID)
	}
	if result.IssuedAtISO != certMap["issued_at"].(string) {
		t.Errorf("IssuedAtISO = %q, want %q", result.IssuedAtISO, certMap["issued_at"].(string))
	}
	// Overall verdict from the cert.
	wantVerdict := certMap["verification"].(map[string]any)["overall_verdict"].(string)
	if result.OverallVerdict != wantVerdict {
		t.Errorf("OverallVerdict = %q, want %q", result.OverallVerdict, wantVerdict)
	}
}

// --- Test (b): v2 backward-compat proof on the same real v3 cert ---
//
// The v3 cert carries BOTH signable_v2_signature (= witness_signature) AND
// signable_v3_signature. A v0.5.x-style verification (using witness_signature
// via the v2 path) must still succeed — confirming that the dual-protocol
// architecture is invisible to old SDKs (PRD criterion #8).
//
// Implementation: we forge a modified cert map that removes
// signable_protocol_version_emitted (or sets it to 0) so the pipeline
// takes the v2 branch. witness_signature is untouched (it IS the v2 sig).

func TestDeriveV3SignedBytes_V2BackwardCompat_SameRealCert(t *testing.T) {
	certData := loadV3Fixture(t, "real-v3-cert.fixture.json")
	var rawCert map[string]any
	if err := json.Unmarshal(certData, &rawCert); err != nil {
		t.Fatalf("parse real-v3-cert.fixture.json: %v", err)
	}

	// Deep-copy so we don't mutate rawCert (JSON round-trip).
	b, _ := json.Marshal(rawCert)
	var v2Cert map[string]any
	_ = json.Unmarshal(b, &v2Cert)

	// Remove v3 dispatch signal → pipeline falls back to v2 path.
	delete(v2Cert, "signable_protocol_version_emitted")
	delete(v2Cert, "signable_v3_signature")
	// witness_signature and signable_v2_signature are byte-identical; keep
	// witness_signature (the v2-path field).

	keyID, pubBase64 := loadProductionWitnessPublicKey(t)
	pubBytes, err := base64.StdEncoding.DecodeString(pubBase64)
	if err != nil {
		t.Fatalf("decode production public key: %v", err)
	}

	result, runErr := Run(v2Cert, keyID, pubBytes)
	if runErr != nil {
		t.Fatalf("v2 backward-compat verification failed: %v\n"+
			"witness_signature must equal signable_v2_signature on a v3 cert (PRD criterion #8).",
			runErr)
	}

	// Confirm the pipeline used the v2 path.
	if result.SignableVersion != "v2" {
		t.Errorf("SignableVersion = %q, want %q (should use v2 path when signable_protocol_version_emitted absent)",
			result.SignableVersion, "v2")
	}
	// CertificateID must still match (same cert, just v2 path).
	if result.CertificateID != rawCert["certificate_id"].(string) {
		t.Errorf("CertificateID mismatch on v2 backward-compat path")
	}
}

// --- Test (c): issued_at trailing-zeros regression (H6) ---
//
// The gateway protojson marshaller may emit issued_at with trailing zeros
// on the nanoseconds fraction:
//   "2026-06-10T00:01:59.878143387000000000Z"  (protojson zero-padded)
// while the witness signs:
//   "2026-06-10T00:01:59.878143387Z"            (RFC3339Nano stripped)
//
// normalizeIssuedAt must strip those trailing zeros before placing the
// string in signable bytes. This test verifies that a cert with a
// zero-padded issued_at string produces the SAME canonical bytes as the
// same cert with a stripped issued_at string.

func TestNormalizeIssuedAt_TrailingZerosStripped(t *testing.T) {
	// RFC3339Nano strips trailing zeros.
	cases := []struct {
		input string
		want  string
	}{
		{
			// No trailing zeros — already canonical.
			input: "2026-06-10T00:01:59.878143387Z",
			want:  "2026-06-10T00:01:59.878143387Z",
		},
		{
			// protojson zero-padded full nanosecond precision.
			input: "2026-06-10T00:01:59.878143387000000000Z",
			want:  "2026-06-10T00:01:59.878143387Z",
		},
		{
			// Partial trailing zeros.
			input: "2026-06-10T00:01:59.100000000Z",
			want:  "2026-06-10T00:01:59.1Z",
		},
		{
			// Whole seconds — RFC3339Nano emits no decimal.
			input: "2026-06-10T00:01:59.000000000Z",
			want:  "2026-06-10T00:01:59Z",
		},
		{
			// Non-UTC offset normalizes to UTC.
			// Go RFC3339Nano reformat emits UTC only when called with UTC().
			input: "2026-06-10T02:01:59.878143387+02:00",
			want:  "2026-06-10T00:01:59.878143387Z",
		},
		{
			// Malformed — returned unchanged (fail-open).
			input: "not-a-timestamp",
			want:  "not-a-timestamp",
		},
	}

	for _, tc := range cases {
		got := normalizeIssuedAt(tc.input)
		if got != tc.want {
			t.Errorf("normalizeIssuedAt(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestDeriveV3SignedBytes_TrailingZeroIssuedAt_RoundTrip verifies that a
// zero-padded issued_at produces the same Ed25519 verification result as
// the canonical RFC3339Nano form. This is the real-cert round-trip variant
// of the H6 check: we feed the cert with an artificially zero-padded
// issued_at and confirm the v3 signature still verifies.
func TestDeriveV3SignedBytes_TrailingZeroIssuedAt_RoundTrip(t *testing.T) {
	certData := loadV3Fixture(t, "real-v3-cert.fixture.json")
	var rawCert map[string]any
	if err := json.Unmarshal(certData, &rawCert); err != nil {
		t.Fatalf("parse real-v3-cert.fixture.json: %v", err)
	}

	// Deep-copy, then pad issued_at with trailing zeros.
	b, _ := json.Marshal(rawCert)
	var paddedCert map[string]any
	_ = json.Unmarshal(b, &paddedCert)

	origIssuedAt := paddedCert["issued_at"].(string)
	if !strings.HasSuffix(origIssuedAt, "Z") {
		t.Fatalf("fixture issued_at does not end in Z: %q", origIssuedAt)
	}
	// Pad: insert trailing zeros before the Z.
	paddedIssuedAt := origIssuedAt[:len(origIssuedAt)-1] + "000000000Z"
	if paddedIssuedAt == origIssuedAt {
		// Already fully padded — construct a known-padded form.
		paddedIssuedAt = "2026-06-10T00:01:59.878143387000000000Z"
	}
	paddedCert["issued_at"] = paddedIssuedAt

	keyID, pubBase64 := loadProductionWitnessPublicKey(t)
	pubBytes, err := base64.StdEncoding.DecodeString(pubBase64)
	if err != nil {
		t.Fatalf("decode production public key: %v", err)
	}

	result, runErr := Run(paddedCert, keyID, pubBytes)
	if runErr != nil {
		t.Fatalf("H6 regression: padded issued_at %q failed verification: %v\n"+
			"normalizeIssuedAt must strip trailing zeros before placing issued_at in signable bytes.",
			paddedIssuedAt, runErr)
	}
	if result.SignableVersion != "v3" {
		t.Errorf("SignableVersion = %q, want %q", result.SignableVersion, "v3")
	}
}

// --- v3 key-count freeze test ---
//
// Structural companion to the v2 7-key freeze test
// (TestDeriveSignedBytes_SignableContainsExactlySevenKeys). Locks the v3
// map at exactly 13 keys. Any addition = v4; any removal = byte-identity break.

func TestDeriveV3SignedBytes_SignableContainsExactlyThirteenKeys(t *testing.T) {
	out, err := DeriveV3SignedBytes(DeriveV3SignedBytesInput{
		CertificateID:          "veil_oracle_0000000000000001",
		RequestID:              "req_oracle_0000000000000001",
		ClaimRequestIDs:        []string{"req_oracle_0000000000000001"},
		ClaimIDs:               []string{"clm_oracle_dsa-bridge"},
		IssuedAt:               "2026-04-20T05:24:12.710321721Z",
		OverallVerdictFullName: "VERDICT_VERIFIED",
		WitnessKeyID:           "witness_v1",
		// Omit optional fields → nil/false → canonical null / false.
	})
	if err != nil {
		t.Fatalf("DeriveV3SignedBytes returned error: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("v3 signable bytes are not valid JSON: %v", err)
	}

	wantKeys := []string{
		"api_key_id", "byok_exempt", "certificate_id", "claim_ids",
		"client_id", "issued_at", "overall_verdict", "protocol_version",
		"redaction_manifest_hash", "request_id", "sanitized_fields_body_hash",
		"tms_manifest_hash", "witness_key_id",
	}
	if len(decoded) != len(wantKeys) {
		t.Fatalf("v3 signable has %d keys, want %d (13-key invariant):\n  got keys: %v",
			len(decoded), len(wantKeys), keysOf(decoded))
	}
	for _, k := range wantKeys {
		if _, ok := decoded[k]; !ok {
			t.Errorf("v3 signable missing required key %q", k)
		}
	}
}

// keysOf returns sorted key names from a map for diagnostic messages.
func keysOf(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
