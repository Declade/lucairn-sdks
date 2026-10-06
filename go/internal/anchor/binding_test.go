package anchor

import (
	"encoding/hex"
	"testing"
	"time"
)

// Golden vector shared with dual-sandbox-architecture
// services/veil-witness/internal/anchorbinding/binding_test.go. Computed
// independently with Python hashlib.
func TestDigestV1_GoldenVector(t *testing.T) {
	certHash := make([]byte, 32)
	for i := range certHash {
		certHash[i] = 0x11
	}
	signable := []byte(`{"certificate_id":"veil_golden","issued_at":"2026-10-06T12:00:00Z"}`)
	h := DigestV1(certHash, signable)
	if got := hex.EncodeToString(h); got != "75310ddd7a1a48b9bc8fa7dccc2640b887a1c865906a5c4f433b4153ff2384da" {
		t.Fatalf("DigestV1 = %s", got)
	}
	if got := RekorDigestV1(h); got != "f9f301e78c77b3a4af4c062703789168cd7b29d843281a8352f04edfc6da3b95368af2482b1d348dfc6767291184d398a5189e748a545c1c9eb98586f6207f35" {
		t.Fatalf("RekorDigestV1 = %s", got)
	}
}

func TestBindingV1Cutover_IsUTCAndAfterS1(t *testing.T) {
	if BindingV1Cutover.Location() != time.UTC {
		t.Fatal("cutover must be UTC")
	}
	// S1 shipped 2026-10-06 without binding; the cutover can never precede it.
	if !BindingV1Cutover.After(time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("cutover precedes the first possible binding-v1 deploy")
	}
}
