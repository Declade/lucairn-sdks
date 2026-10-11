package lucairn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Parity-corpus case tamper_witness_signature_small_order_r (corpus v1.2.3),
// copied verbatim to internal/verify/testdata; the same bytes sit in the
// TypeScript and Python test folders. Both witness signatures are made with
// nonce 0, so R is the identity. crypto/ed25519 by itself accepts that
// signature; the witness-only VerifyCertificate refuses it as an invalid
// signature by the SDK's own rule (T-1322). The witness key is the published
// corpus TEST key.
const (
	corpusSmallOrderRSHA256 = "2fc78fe50a778c53d421f4af4e85c9d5a39a1e0b25c37bcd1aa4203465e89db6"
	corpusWitnessKeyID      = "witness_parity_v1"
	corpusWitnessPublicKey  = "DADdf3OIOXxhBl2VQ5k1Kk8VgCTNBVhrWolquUvskSc="
)

func TestVerifyCertificate_CorpusSmallOrderRRefused(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("internal", "verify", "testdata", "corpus-tamper_witness_signature_small_order_r.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != corpusSmallOrderRSHA256 {
		t.Fatalf("corpus case sha256 = %s, want %s", got, corpusSmallOrderRSHA256)
	}
	var c struct {
		Certificate json.RawMessage `json:"certificate"`
		Expected    map[string]struct {
			Verdict string `json:"verdict"`
			Reason  string `json:"reason"`
		} `json:"expected"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if want := c.Expected["default"]; want.Verdict != "FAILED" || want.Reason != "witness_signature_invalid" {
		t.Fatalf("corpus expectation changed: %+v", want)
	}
	for _, mv := range []string{"", "v3"} {
		got, err := VerifyCertificate([]byte(c.Certificate), VerifyCertificateKeys{
			WitnessKeyID:           corpusWitnessKeyID,
			WitnessPublicKey:       corpusWitnessPublicKey,
			MinimumSignableVersion: mv,
		})
		if err == nil {
			t.Fatalf("policy %q: small-order R accepted: %+v", mv, *got)
		}
		assertReason(t, err, ReasonInvalidSignature)
	}
}

// certOutcome is VerifyCertificate as one comparable string:
// "accept:<v2|v3>" or "refuse:<reason>".
func certOutcome(t *testing.T, cert any, keys VerifyCertificateKeys) string {
	t.Helper()
	r, err := VerifyCertificate(cert, keys)
	if err == nil {
		return "accept:" + r.SignableVersion
	}
	var ce *CertificateError
	if !errors.As(err, &ce) {
		t.Fatalf("unexpected error type %T: %v", err, err)
	}
	return "refuse:" + string(ce.Reason)
}

func corpusKeys() VerifyCertificateKeys {
	return VerifyCertificateKeys{WitnessKeyID: corpusWitnessKeyID, WitnessPublicKey: corpusWitnessPublicKey}
}

// corpusCase reads a parity-corpus case copied verbatim to
// internal/verify/testdata (same bytes in the TypeScript and Python test
// folders) and returns the RAW text of its certificate and the expected
// reason.
func corpusCase(t *testing.T, name, wantSHA256 string) (json.RawMessage, string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("internal", "verify", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != wantSHA256 {
		t.Fatalf("%s sha256 = %s, want %s", name, got, wantSHA256)
	}
	var c struct {
		Certificate json.RawMessage `json:"certificate"`
		Expected    map[string]struct {
			Reason string `json:"reason"`
		} `json:"expected"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	return c.Certificate, c.Expected["default"].Reason
}

func productionKeys(t *testing.T) VerifyCertificateKeys {
	t.Helper()
	k := loadFixture(t, "production-witness-pubkey.json")
	return VerifyCertificateKeys{WitnessKeyID: k["witnessKeyId"].(string), WitnessPublicKey: k["publicKeyBase64"].(string)}
}

// The number TOKEN 2.0000000000000001 for protocol_version: refused as
// malformed when the SDK reads the raw text; a caller's own json.Unmarshal
// turns it into the value 2, so map input is judged by value and accepted.
func TestVerifyCertificate_CorpusFloatTokenProtocolVersion(t *testing.T) {
	raw, want := corpusCase(t, "corpus-tamper_protocol_version_float_token.json", "e9a576edf871084cf187832b5e7d9506dc8df26641182f78343cf20517c5b69f")
	if want != "malformed" {
		t.Fatalf("corpus expectation changed: %s", want)
	}
	if got := certOutcome(t, []byte(raw), corpusKeys()); got != "refuse:malformed" {
		t.Errorf("[]byte input: %s", got)
	}
	if got := certOutcome(t, raw, corpusKeys()); got != "refuse:malformed" {
		t.Errorf("json.RawMessage input: %s", got)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["protocol_version"] != float64(2) {
		t.Fatalf("decoded protocol_version = %v", m["protocol_version"])
	}
	if got := certOutcome(t, m, corpusKeys()); got != "accept:v3" {
		t.Errorf("map input (value 2): %s", got)
	}
}

func TestVerifyCertificate_CorpusOversizedIntegerProtocolVersion(t *testing.T) {
	raw, want := corpusCase(t, "corpus-tamper_protocol_version_oversized_integer.json", "0920687b2cd9b01a68689dd2903045fceebcd06ea9186c19635ef8b6056e2bfb")
	if want != "malformed" {
		t.Fatalf("corpus expectation changed: %s", want)
	}
	if got := certOutcome(t, []byte(raw), corpusKeys()); got != "refuse:malformed" {
		t.Errorf("[]byte input: %s", got)
	}
}

func TestVerifyCertificate_CorpusV3SignatureControlChar(t *testing.T) {
	raw, want := corpusCase(t, "corpus-tamper_signable_v3_signature_control_char.json", "f2deec7b3549ab30e42a67a29a70c2b566b42528ea6d1c43ffd2da16e4c35bb2")
	if want != "version_downgrade_detected" {
		t.Fatalf("corpus expectation changed: %s", want)
	}
	if got := certOutcome(t, []byte(raw), corpusKeys()); got != "refuse:version_downgrade_detected" {
		t.Errorf("[]byte input: %s", got)
	}
}

// A genuine certificate with the ordinary protocol_version 2 verifies with
// raw bytes AND with map input: the recorded v3 certificate (production
// public key) and the v2 fixture.
func TestVerifyCertificate_GenuineCertificatesRawAndMap(t *testing.T) {
	realRaw, err := os.ReadFile(filepath.Join("internal", "verify", "testdata", "real-v3-cert.fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	v2Raw, err := os.ReadFile(filepath.Join(tsFixturesDir(t), "cert-valid-anchored.json"))
	if err != nil {
		t.Fatal(err)
	}
	v2Keys := VerifyCertificateKeys{WitnessKeyID: "witness_v1", WitnessPublicKey: witnessKeypair(t)["publicKey"]}
	for _, c := range []struct {
		name string
		raw  []byte
		keys VerifyCertificateKeys
		want string
	}{
		{"recorded v3", realRaw, productionKeys(t), "accept:v3"},
		{"v2 fixture", v2Raw, v2Keys, "accept:v2"},
	} {
		var m map[string]any
		if err := json.Unmarshal(c.raw, &m); err != nil {
			t.Fatal(err)
		}
		if m["protocol_version"] != float64(2) {
			t.Fatalf("%s: protocol_version = %v", c.name, m["protocol_version"])
		}
		if got := certOutcome(t, c.raw, c.keys); got != c.want {
			t.Errorf("%s, []byte: %s", c.name, got)
		}
		if got := certOutcome(t, json.RawMessage(c.raw), c.keys); got != c.want {
			t.Errorf("%s, json.RawMessage: %s", c.name, got)
		}
		if got := certOutcome(t, m, c.keys); got != c.want {
			t.Errorf("%s, map: %s", c.name, got)
		}
	}
}

// The shared certificate_field_vectors: one signature TEXT field of a base
// certificate is replaced; raw bytes and map input must both give the
// expected result.
func TestVerifyCertificate_SharedFieldVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("internal", "verify", "testdata", "ed25519-rule-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != "26033d6336fd735dc5c4db068fbcb682cbd6385f8167b8afbb5d44769062fd20" {
		t.Fatalf("ed25519-rule-vectors.json sha256 = %s (the file must be identical in the three SDKs)", got)
	}
	var doc struct {
		Fields []struct {
			ID       string `json:"id"`
			Base     string `json:"base"`
			Field    string `json:"field"`
			Text     string `json:"text"`
			Expected string `json:"expected"`
		} `json:"certificate_field_vectors"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Fields) != 76 {
		t.Fatalf("%d field vectors, want 76", len(doc.Fields))
	}
	v2Keys := VerifyCertificateKeys{WitnessKeyID: "witness_v1", WitnessPublicKey: witnessKeypair(t)["publicKey"]}
	v3Keys := productionKeys(t)
	for _, v := range doc.Fields {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			var cert map[string]any
			keys := v2Keys
			switch v.Base {
			case "v2":
				cert = loadFixture(t, "cert-valid-anchored.json")
			case "v3":
				cert = loadFixture(t, "cert-real-v3-production.json")
				keys = v3Keys
			default:
				t.Fatalf("base %q", v.Base)
			}
			cert[v.Field] = v.Text
			if got := certOutcome(t, cert, keys); got != v.Expected {
				t.Errorf("map input: got %s, want %s", got, v.Expected)
			}
			raw, err := json.Marshal(cert)
			if err != nil {
				t.Fatal(err)
			}
			if got := certOutcome(t, raw, keys); got != v.Expected {
				t.Errorf("raw bytes input: got %s, want %s", got, v.Expected)
			}
		})
	}
}
