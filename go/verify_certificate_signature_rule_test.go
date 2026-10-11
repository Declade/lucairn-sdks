package lucairn

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
