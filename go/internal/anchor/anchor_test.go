package anchor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPinnedRootsMatchChecksums(t *testing.T) {
	got := sha256.Sum256(FreeTSARootPEM)
	if hex.EncodeToString(got[:]) != FreeTSARootSHA256 {
		t.Fatalf("freetsa.pem checksum drifted: %x", got)
	}
	rk, err := ParseRekorKeyPEM(RekorPublicGoodPEM)
	if err != nil {
		t.Fatal(err)
	}
	if rk.LogID != RekorPublicGoodLogID {
		t.Fatalf("Rekor log ID %s != pinned %s", rk.LogID, RekorPublicGoodLogID)
	}
	f := sha256.Sum256(RekorPublicGoodPEM)
	if hex.EncodeToString(f[:]) != "dce5ef715502ec9f3cdfd11f8cc384b31a6141023d3e7595e9908a81cb6241bd" {
		t.Fatalf("rekor-public-good.pem file checksum drifted: %x", f)
	}
}

func freeTSAPool(t *testing.T) *x509.CertPool {
	t.Helper()
	p := x509.NewCertPool()
	if !p.AppendCertsFromPEM(FreeTSARootPEM) {
		t.Fatal("pinned FreeTSA root does not load")
	}
	return p
}

// realToken is the FreeTSA response stored on a real production certificate
// (the SDK's real-v3-cert fixture, 2026-06-10).
func realToken(t *testing.T) (token, digest []byte) {
	t.Helper()
	b, err := os.ReadFile("../verify/testdata/real-v3-cert.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Attestation struct {
			Timestamp struct {
				Token    string `json:"timestamp_token"`
				CertHash string `json:"cert_hash"`
			} `json:"timestamp"`
		} `json:"attestation"`
	}
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	token, _ = base64.StdEncoding.DecodeString(c.Attestation.Timestamp.Token)
	digest, _ = base64.StdEncoding.DecodeString(c.Attestation.Timestamp.CertHash)
	return token, digest
}

func TestVerifyTimestamp_RealFreeTSAToken(t *testing.T) {
	token, digest := realToken(t)
	res, err := VerifyTimestamp(token, digest, freeTSAPool(t), time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("real FreeTSA token must verify: %v", err)
	}
	if res.GenTime.Format(time.RFC3339) != "2026-06-10T00:01:59Z" {
		t.Fatalf("genTime = %s", res.GenTime)
	}
	if !strings.Contains(res.Signer, "freetsa") {
		t.Fatalf("signer = %s", res.Signer)
	}
}

func TestVerifyTimestamp_RealToken_Mutations(t *testing.T) {
	token, digest := realToken(t)
	pool := freeTSAPool(t)
	now := time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)

	other := append([]byte(nil), digest...)
	other[0] ^= 1
	if _, err := VerifyTimestamp(token, other, pool, now); err == nil {
		t.Fatal("token over other bytes must fail")
	}
	// Flip one bit at every position of the token. A flip may only survive
	// inside bytes no signature covers (the unsigned CMS digestAlgorithms
	// set, extra chain certificates the token carries, the PKIStatus
	// envelope); it must then leave every verified value unchanged, and no
	// flip inside the TSTInfo (located by its message imprint) may survive.
	base, _ := VerifyTimestamp(token, digest, pool, now)
	at := bytes.Index(token, digest)
	if at < 0 {
		t.Fatal("imprint not found in token")
	}
	survived := 0
	for i := 0; i < len(token); i++ {
		m := append([]byte(nil), token...)
		m[i] ^= 0x01
		res, err := VerifyTimestamp(m, digest, pool, now)
		if err != nil {
			continue
		}
		survived++
		if !res.GenTime.Equal(base.GenTime) || res.Signer != base.Signer {
			t.Fatalf("byte flip at %d changed a verified value and still verified", i)
		}
		if i >= at-40 && i < at+len(digest)+40 {
			t.Fatalf("byte flip at %d inside the TSTInfo still verifies", i)
		}
	}
	t.Logf("%d of %d single-bit flips landed in unsigned envelope bytes (verified values unchanged)", survived, len(token))
	if _, err := VerifyTimestamp(token, digest, x509.NewCertPool(), now); err == nil {
		t.Fatal("unpinned root must fail")
	}
}

func realRekor(t *testing.T) (RekorEntry, *RekorKey) {
	t.Helper()
	b, err := os.ReadFile("testdata/rekor_real_entry.json")
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogIndex       int64  `json:"logIndex"`
		Verification   struct {
			InclusionProof       json.RawMessage `json:"inclusionProof"`
			SignedEntryTimestamp string          `json:"signedEntryTimestamp"`
		} `json:"verification"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	rk, err := ParseRekorKeyPEM(RekorPublicGoodPEM)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range env {
		body, _ := base64.StdEncoding.DecodeString(e.Body)
		set, _ := base64.StdEncoding.DecodeString(e.Verification.SignedEntryTimestamp)
		return RekorEntry{LogIndex: e.LogIndex, InclusionProof: e.Verification.InclusionProof,
			SignedEntryTimestamp: set, CanonicalBody: body, IntegratedTime: e.IntegratedTime}, rk
	}
	t.Fatal("empty fixture")
	return RekorEntry{}, nil
}

func TestRekor_RealEntry_SETInclusionCheckpoint(t *testing.T) {
	e, rk := realRekor(t)
	if err := VerifySET(e.CanonicalBody, e.IntegratedTime, e.LogIndex, e.SignedEntryTimestamp, rk); err != nil {
		t.Fatalf("real SET must verify: %v", err)
	}
	cp, err := verifyInclusion(e.CanonicalBody, e.InclusionProof, rk)
	if err != nil || !cp {
		t.Fatalf("real inclusion proof + checkpoint must verify: cp=%v err=%v", cp, err)
	}
	// The real entry is somebody else's "rekord": the witness-key check must refuse it.
	pub, _, _ := ed25519.GenerateKey(nil)
	if _, err := VerifyRekor(e, rk, pub); err == nil {
		t.Fatal("an entry not made by the witness must fail")
	}
	// SET binds index, time and body.
	if VerifySET(e.CanonicalBody, e.IntegratedTime+1, e.LogIndex, e.SignedEntryTimestamp, rk) == nil {
		t.Fatal("SET with altered integratedTime must fail")
	}
	if VerifySET(e.CanonicalBody, e.IntegratedTime, e.LogIndex+1, e.SignedEntryTimestamp, rk) == nil {
		t.Fatal("SET with altered logIndex must fail")
	}
	body := append([]byte(nil), e.CanonicalBody...)
	body[10] ^= 1
	if VerifySET(body, e.IntegratedTime, e.LogIndex, e.SignedEntryTimestamp, rk) == nil {
		t.Fatal("SET with altered body must fail")
	}
	if _, err := verifyInclusion(body, e.InclusionProof, rk); err == nil {
		t.Fatal("inclusion with altered body must fail")
	}
}
