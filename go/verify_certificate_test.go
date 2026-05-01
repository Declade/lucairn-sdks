package lucairn

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// -- Happy paths ----------------------------------------------------------

func TestVerifyCertificate_HappyPath_Anchored(t *testing.T) {
	cert := loadFixture(t, "cert-valid-anchored.json")
	kp := witnessKeypair(t)
	result, err := VerifyCertificate(cert, VerifyCertificateKeys{
		WitnessKeyID:     "witness_v1",
		WitnessPublicKey: kp["publicKey"],
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.CertificateID != cert["certificate_id"].(string) {
		t.Errorf("CertificateID = %q", result.CertificateID)
	}
	if result.WitnessKeyID != "witness_v1" {
		t.Errorf("WitnessKeyID = %q", result.WitnessKeyID)
	}
	if result.AnchorStatus != AnchorStatusAnchored {
		t.Errorf("AnchorStatus = %q", result.AnchorStatus)
	}
	if result.OverallVerdict != VerdictVerified {
		t.Errorf("OverallVerdict = %q", result.OverallVerdict)
	}
	if result.WitnessAssertedIssuedAtISO != cert["issued_at"].(string) {
		t.Errorf("IssuedAtISO preservation failed")
	}
	// Parity with TS/Python: a parsed time.Time counterpart of the ISO
	// string must also be populated.
	if result.WitnessAssertedIssuedAt.IsZero() {
		t.Errorf("WitnessAssertedIssuedAt should be populated on happy path")
	}
	if result.WitnessAssertedIssuedAt.Year() != 2026 {
		t.Errorf("WitnessAssertedIssuedAt year = %d, want 2026", result.WitnessAssertedIssuedAt.Year())
	}
}

func TestVerifyCertificate_HappyPath_Pending(t *testing.T) {
	cert := loadFixture(t, "cert-valid-pending.json")
	kp := witnessKeypair(t)
	result, err := VerifyCertificate(cert, VerifyCertificateKeys{
		WitnessKeyID:     "witness_v1",
		WitnessPublicKey: kp["publicKey"],
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AnchorStatus != AnchorStatusPending {
		t.Errorf("AnchorStatus = %q", result.AnchorStatus)
	}
}

func TestVerifyCertificate_HappyPath_Failed(t *testing.T) {
	cert := loadFixture(t, "cert-valid-failed.json")
	kp := witnessKeypair(t)
	result, err := VerifyCertificate(cert, VerifyCertificateKeys{
		WitnessKeyID:     "witness_v1",
		WitnessPublicKey: kp["publicKey"],
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AnchorStatus != AnchorStatusFailed {
		t.Errorf("AnchorStatus = %q", result.AnchorStatus)
	}
}

// -- Go-oracle cross-check (critical) ------------------------------------

// The authoritative "does the Go port agree with the Go assembler
// end-to-end" test. If this ever fails after a gateway change, the
// server-side signable-field encoding changed and the Go SDK port must
// match. Do NOT paper over by regenerating fixtures.
func TestVerifyCertificate_GoOracleCrossCheck(t *testing.T) {
	cert := loadFixture(t, "cert-go-signed-reference.json")
	kp := witnessKeypair(t) // prefers test-witness-keypair.json
	result, err := VerifyCertificate(cert, VerifyCertificateKeys{
		WitnessKeyID:     "witness_v1",
		WitnessPublicKey: kp["publicKey"],
	})
	if err != nil {
		t.Fatalf("oracle cert failed to verify: %v", err)
	}
	if result.CertificateID != "veil_oracle_0000000000000001" {
		t.Errorf("CertificateID = %q", result.CertificateID)
	}
	if result.OverallVerdict != VerdictVerified {
		t.Errorf("OverallVerdict = %q", result.OverallVerdict)
	}
}

// -- Failure reasons ------------------------------------------------------

func TestVerifyCertificate_MalformedOnNonObject(t *testing.T) {
	kp := witnessKeypair(t)
	keys := VerifyCertificateKeys{
		WitnessKeyID:     "witness_v1",
		WitnessPublicKey: kp["publicKey"],
	}
	for _, bad := range []any{nil, "string", []any{}, 42, 1.5} {
		_, err := VerifyCertificate(bad, keys)
		if err == nil {
			t.Errorf("bad=%v: expected error", bad)
			continue
		}
		var certErr *CertificateError
		if !errors.As(err, &certErr) {
			t.Errorf("bad=%v: want CertificateError, got %T", bad, err)
			continue
		}
		if certErr.Reason != ReasonMalformed {
			t.Errorf("bad=%v: reason = %q", bad, certErr.Reason)
		}
	}
}

func TestVerifyCertificate_MalformedOnMissingFields(t *testing.T) {
	cert := loadFixture(t, "cert-malformed-truncated.json")
	_, err := VerifyCertificate(cert, witnessKeys(t))
	assertReason(t, err, ReasonMalformed)
}

func TestVerifyCertificate_MalformedOnRequestIDMismatch(t *testing.T) {
	cert := deepCopyMap(t, loadFixture(t, "cert-valid-anchored.json"))
	cert["request_id"] = "req_different_from_claims"
	_, err := VerifyCertificate(cert, witnessKeys(t))
	assertReason(t, err, ReasonMalformed)
}

func TestVerifyCertificate_MalformedOnUnknownVerdict(t *testing.T) {
	cert := deepCopyMap(t, loadFixture(t, "cert-valid-anchored.json"))
	cert["verification"].(map[string]any)["overall_verdict"] = "VERDICT_FUTURE_VALUE"
	_, err := VerifyCertificate(cert, witnessKeys(t))
	assertReason(t, err, ReasonMalformed)
}

func TestVerifyCertificate_UnsupportedProtocolVersion(t *testing.T) {
	cert := loadFixture(t, "cert-protocol-version-mismatch.json")
	_, err := VerifyCertificate(cert, witnessKeys(t))
	assertReason(t, err, ReasonUnsupportedProtocolVersion)
}

func TestVerifyCertificate_WitnessMismatch(t *testing.T) {
	cert := loadFixture(t, "cert-valid-anchored.json")
	kp := witnessKeypair(t)
	keys := VerifyCertificateKeys{
		WitnessKeyID:     "different-label",
		WitnessPublicKey: kp["publicKey"],
	}
	_, err := VerifyCertificate(cert, keys)
	assertReason(t, err, ReasonWitnessMismatch)
}

func TestVerifyCertificate_WitnessSignatureMissing_Empty(t *testing.T) {
	cert := loadFixture(t, "cert-no-signature.json")
	_, err := VerifyCertificate(cert, witnessKeys(t))
	assertReason(t, err, ReasonWitnessSignatureMissing)
}

func TestVerifyCertificate_WitnessSignatureMissing_Whitespace(t *testing.T) {
	cert := loadFixture(t, "cert-whitespace-signature.json")
	_, err := VerifyCertificate(cert, witnessKeys(t))
	assertReason(t, err, ReasonWitnessSignatureMissing)
}

func TestVerifyCertificate_InvalidSignature_TamperedPayload(t *testing.T) {
	cert := loadFixture(t, "cert-tampered-payload.json")
	_, err := VerifyCertificate(cert, witnessKeys(t))
	assertReason(t, err, ReasonInvalidSignature)
}

func TestVerifyCertificate_InvalidSignature_MalformedPublicKey(t *testing.T) {
	cert := loadFixture(t, "cert-valid-anchored.json")
	// Wrong-length key (16 bytes instead of 32).
	keys := VerifyCertificateKeys{
		WitnessKeyID:     "witness_v1",
		WitnessPublicKey: make([]byte, 16),
	}
	_, err := VerifyCertificate(cert, keys)
	assertReason(t, err, ReasonInvalidSignature)
	var certErr *CertificateError
	if !errors.As(err, &certErr) {
		t.Fatalf("expected CertificateError")
	}
	if certErr.Err == nil {
		t.Errorf("Err should preserve the wrapped normalization error")
	}
}

// -- Ordering lock-in -----------------------------------------------------

func TestVerifyCertificate_MalformedBeforeProtocolVersion(t *testing.T) {
	cert := loadFixture(t, "cert-malformed-plus-bad-version.json")
	_, err := VerifyCertificate(cert, witnessKeys(t))
	assertReason(t, err, ReasonMalformed)
}

func TestVerifyCertificate_UnsupportedProtocolBeforeWitnessCheck(t *testing.T) {
	cert := loadFixture(t, "cert-protocol-version-mismatch.json")
	kp := witnessKeypair(t)
	keys := VerifyCertificateKeys{
		WitnessKeyID:     "wrong-label",
		WitnessPublicKey: kp["publicKey"],
	}
	_, err := VerifyCertificate(cert, keys)
	assertReason(t, err, ReasonUnsupportedProtocolVersion)
}

// -- Gap-fill tests --------------------------------------------------------

func TestVerifyCertificate_MalformedOnEmptyClaims(t *testing.T) {
	cert := deepCopyMap(t, loadFixture(t, "cert-valid-anchored.json"))
	cert["claims"] = []any{}
	_, err := VerifyCertificate(cert, witnessKeys(t))
	assertReason(t, err, ReasonMalformed)
	if !strings.Contains(err.Error(), "empty") {
		t.Errorf("message should mention 'empty': %v", err)
	}
}

func TestVerifyCertificate_MalformedOnEmptyVerdict(t *testing.T) {
	cert := deepCopyMap(t, loadFixture(t, "cert-valid-anchored.json"))
	cert["verification"].(map[string]any)["overall_verdict"] = ""
	_, err := VerifyCertificate(cert, witnessKeys(t))
	assertReason(t, err, ReasonMalformed)
}

func TestVerifyCertificate_RejectsNilKeysWithConfigError(t *testing.T) {
	cert := loadFixture(t, "cert-valid-anchored.json")
	_, err := VerifyCertificate(cert, VerifyCertificateKeys{})
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want ConfigError, got %T", err)
	}
}

// -- Input normalization --------------------------------------------------

func TestVerifyCertificate_AcceptsStructPointerInput(t *testing.T) {
	raw := loadFixture(t, "cert-valid-anchored.json")
	// Marshal → *VeilCertificate, then verify.
	var cert VeilCertificate
	if err := decodeInto(raw, &cert); err != nil {
		t.Fatal(err)
	}
	_, err := VerifyCertificate(&cert, witnessKeys(t))
	if err != nil {
		t.Errorf("struct pointer input: %v", err)
	}
}

func TestVerifyCertificate_AcceptsBytesInput(t *testing.T) {
	fixtures := tsFixturesDir(t)
	data, err := readFile(fixtures, "cert-valid-anchored.json")
	if err != nil {
		t.Fatal(err)
	}
	_, err = VerifyCertificate(data, witnessKeys(t))
	if err != nil {
		t.Errorf("bytes input: %v", err)
	}
}

func TestVerifyCertificate_HappyPath_WithBase64BytesKey(t *testing.T) {
	cert := loadFixture(t, "cert-valid-anchored.json")
	kp := witnessKeypair(t)
	// Decode the base64 string to raw bytes and pass those.
	raw, err := base64.StdEncoding.DecodeString(kp["publicKey"])
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyCertificate(cert, VerifyCertificateKeys{
		WitnessKeyID:     "witness_v1",
		WitnessPublicKey: raw,
	})
	if err != nil {
		t.Fatalf("raw-bytes key: %v", err)
	}
	if result.OverallVerdict != VerdictVerified {
		t.Errorf("OverallVerdict = %q", result.OverallVerdict)
	}
}

// -- Client method delegation ---------------------------------------------

func TestClientVerifyCertificate_Delegates(t *testing.T) {
	cert := loadFixture(t, "cert-valid-anchored.json")
	c, err := New(validAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.VerifyCertificate(cert, witnessKeys(t))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.AnchorStatus != AnchorStatusAnchored {
		t.Errorf("AnchorStatus = %q", result.AnchorStatus)
	}
}

// -- helpers --

func witnessKeys(t *testing.T) VerifyCertificateKeys {
	t.Helper()
	kp := witnessKeypair(t)
	return VerifyCertificateKeys{
		WitnessKeyID:     "witness_v1",
		WitnessPublicKey: kp["publicKey"],
	}
}

func assertReason(t *testing.T, err error, want VerifyCertificateFailureReason) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected CertificateError with reason=%q, got nil", want)
	}
	var certErr *CertificateError
	if !errors.As(err, &certErr) {
		t.Fatalf("want CertificateError, got %T (%v)", err, err)
	}
	if certErr.Reason != want {
		t.Errorf("reason = %q, want %q (message=%q)", certErr.Reason, want, certErr.Message)
	}
}

func readFile(dir, name string) ([]byte, error) {
	return readFileFull(dir, name)
}
