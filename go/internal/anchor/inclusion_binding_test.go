package anchor

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

// synthEntry builds a two-leaf synthetic log holding one hashedrekord made
// by a synthetic witness key, the entry at tree index 1, with a signed
// checkpoint, and a SET over the given global log index. Synthetic only.
func synthEntry(t *testing.T, setIndex int64, withCheckpoint bool) (RekorEntry, *RekorKey, ed25519.PublicKey) {
	t.Helper()
	wpub, wpriv, _ := ed25519.GenerateKey(rand.Reader)
	digest := sha512.Sum512([]byte("synthetic stored certificate"))
	sig, err := wpriv.Sign(nil, digest[:], &ed25519.Options{Hash: crypto.SHA512})
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKIXPublicKey(wpub)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	body := []byte(fmt.Sprintf(`{"apiVersion":"0.0.1","kind":"hashedrekord","spec":{"data":{"hash":{"algorithm":"sha512","value":"%s"}},"signature":{"content":"%s","publicKey":{"content":"%s"}}}}`,
		hex.EncodeToString(digest[:]), base64.StdEncoding.EncodeToString(sig), base64.StdEncoding.EncodeToString(pubPEM)))

	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	spki, _ := x509.MarshalPKIXPublicKey(&lk.PublicKey)
	id := sha256.Sum256(spki)
	rk := &RekorKey{Public: &lk.PublicKey, LogID: hex.EncodeToString(id[:])}

	filler := sha256.Sum256(append([]byte{0}, []byte("filler")...))
	leaf := sha256.Sum256(append([]byte{0}, body...))
	root := nodeHash(filler[:], leaf[:])
	proof := map[string]any{"hashes": []string{hex.EncodeToString(filler[:])}, "logIndex": 1, "rootHash": hex.EncodeToString(root), "treeSize": 2}
	if withCheckpoint {
		note := "synthetic.invalid - 1\n2\n" + base64.StdEncoding.EncodeToString(root) + "\n"
		nd := sha256.Sum256([]byte(note))
		nsig, _ := ecdsa.SignASN1(rand.Reader, lk, nd[:])
		hint, _ := hex.DecodeString(rk.LogID[:8])
		proof["checkpoint"] = note + "\n— synthetic.invalid " + base64.StdEncoding.EncodeToString(append(hint, nsig...)) + "\n"
	}
	pj, _ := json.Marshal(proof)
	itime := int64(1790000000)
	payload := `{"body":"` + base64.StdEncoding.EncodeToString(body) + `","integratedTime":` + strconv.FormatInt(itime, 10) +
		`,"logID":"` + rk.LogID + `","logIndex":` + strconv.FormatInt(setIndex, 10) + `}`
	pd := sha256.Sum256([]byte(payload))
	set, _ := ecdsa.SignASN1(rand.Reader, lk, pd[:])
	return RekorEntry{LogIndex: setIndex, InclusionProof: pj, SignedEntryTimestamp: set, CanonicalBody: body, IntegratedTime: itime}, rk, wpub
}

// F1 (T-1231 S1 round-1 gate): a proof without a signed checkpoint is a
// FAILURE (its root is an unsigned number), and the proof's tree index may
// not exceed the SET-signed log index.
func TestRekorInclusionRequiresCheckpointAndBindsIndex(t *testing.T) {
	e, rk, w := synthEntry(t, 1, true)
	res, err := VerifyRekor(e, rk, w)
	if err != nil || !res.Checkpoint {
		t.Fatalf("well-formed entry: %v %+v", err, res)
	}
	e, rk, w = synthEntry(t, 7, true) // a later shard: global index above the tree index
	if _, err := VerifyRekor(e, rk, w); err != nil {
		t.Fatalf("tree index below the global index must pass: %v", err)
	}
	e, rk, w = synthEntry(t, 0, true)
	if _, err := VerifyRekor(e, rk, w); err == nil || !strings.Contains(err.Error(), "above the signed log index") {
		t.Fatalf("tree index above the signed index must fail, got %v", err)
	}
	e, rk, w = synthEntry(t, 1, false)
	if _, err := VerifyRekor(e, rk, w); err == nil || !strings.Contains(err.Error(), "no signed checkpoint") {
		t.Fatalf("missing checkpoint must fail, got %v", err)
	}
}
