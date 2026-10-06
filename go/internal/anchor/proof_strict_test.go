package anchor

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The Rekor inclusion-proof JSON a bundle carries is unsigned bundle content
// (the signed parts are the entry timestamp and the checkpoint). It is read
// as ONE strict document, on the certificate path and on the audit-root path
// alike (both go through verifyInclusion): a byte string has exactly one
// reading (gate record "Sol #79", T11).
//
// Measured on a REAL production entry of the public-good log
// (testdata/rekor_real_entry.json): the genuine proof still verifies, and
// every respelling below — each of which Go's lenient json.Unmarshal reads as
// the genuine proof — is refused.
func TestInclusionProofJSONIsStrict(t *testing.T) {
	e, rk := realRekor(t)
	genuine := e.InclusionProof
	if cp, _, err := verifyInclusion(e.CanonicalBody, genuine, rk); err != nil || !cp {
		t.Fatalf("the real entry's own proof must verify under the strict decoder: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(genuine, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != len(inclusionProofKeys) {
		t.Fatalf("the real proof has %d keys, the decoder knows %d", len(fields), len(inclusionProofKeys))
	}
	for k := range fields {
		if !inclusionProofKeys[k] {
			t.Fatalf("the real proof carries key %q, which the strict decoder would refuse", k)
		}
	}
	// compact is the same proof in a compact, fixed key order, so the
	// mutations below are plain string edits.
	obj := func(pairs ...string) []byte {
		var b bytes.Buffer
		b.WriteByte('{')
		for i := 0; i < len(pairs); i += 2 {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(`"` + pairs[i] + `":` + pairs[i+1])
		}
		b.WriteByte('}')
		return b.Bytes()
	}
	f := func(k string) string { return string(fields[k]) }
	wrongRoot := `"` + strings.Repeat("00", 32) + `"`
	base := []string{"checkpoint", f("checkpoint"), "hashes", f("hashes"), "logIndex", f("logIndex"), "rootHash", f("rootHash"), "treeSize", f("treeSize")}
	with := func(extra ...string) []byte { return obj(append(append([]string(nil), base...), extra...)...) }
	if _, _, err := verifyInclusion(e.CanonicalBody, obj(base...), rk); err != nil {
		t.Fatalf("premise: the compact respelling of the real proof verifies: %v", err)
	}

	cases := map[string][]byte{
		// Sol's input: a wrong rootHash, then the genuine one (the later
		// duplicate wins in a lenient decoder).
		"duplicate rootHash, wrong then genuine": obj("checkpoint", f("checkpoint"), "hashes", f("hashes"), "logIndex", f("logIndex"),
			"rootHash", wrongRoot, "rootHash", f("rootHash"), "treeSize", f("treeSize")),
		"duplicate rootHash, both genuine": with("rootHash", f("rootHash")),
		"duplicate treeSize":               with("treeSize", f("treeSize")),
		"duplicate checkpoint":             with("checkpoint", f("checkpoint")),
		"duplicate key spelled with an escape": obj("checkpoint", f("checkpoint"), "hashes", f("hashes"), "logIndex", f("logIndex"),
			`rootHash`, wrongRoot, "rootHash", f("rootHash"), "treeSize", f("treeSize")),
		// Go's decoder matches struct fields case-insensitively.
		"case-variant key RootHash":   with("RootHash", wrongRoot),
		"case-variant key roothash":   with("roothash", f("rootHash")),
		"case-variant key TREESIZE":   with("TREESIZE", f("treeSize")),
		"case-variant key Checkpoint": with("Checkpoint", f("checkpoint")),
		"only case-variant keys": obj("Checkpoint", f("checkpoint"), "Hashes", f("hashes"), "LogIndex", f("logIndex"),
			"RootHash", f("rootHash"), "TreeSize", f("treeSize")),
		"unknown key":                   with("extra", `"x"`),
		"unknown key holding an object": with("verification", `{}`),
		"trailing object":               append(with(), []byte(`{}`)...),
		"trailing garbage":              append(with(), []byte(` x`)...),
		"trailing second proof":         append(with(), with()...),
		"trailing bracket":              append(with(), ']'),
		"wrapped in an array":           append(append([]byte(`[`), with()...), ']'),
		"logIndex as a string": obj("checkpoint", f("checkpoint"), "hashes", f("hashes"), "logIndex", `"`+f("logIndex")+`"`,
			"rootHash", f("rootHash"), "treeSize", f("treeSize")),
		"treeSize with a fraction": obj("checkpoint", f("checkpoint"), "hashes", f("hashes"), "logIndex", f("logIndex"),
			"rootHash", f("rootHash"), "treeSize", f("treeSize")+".0"),
		"treeSize with an exponent": obj("checkpoint", f("checkpoint"), "hashes", f("hashes"), "logIndex", f("logIndex"),
			"rootHash", f("rootHash"), "treeSize", f("treeSize")+"e0"),
		"logIndex with a leading zero": obj("checkpoint", f("checkpoint"), "hashes", f("hashes"), "logIndex", "0"+f("logIndex"),
			"rootHash", f("rootHash"), "treeSize", f("treeSize")),
		"rootHash null": obj("checkpoint", f("checkpoint"), "hashes", f("hashes"), "logIndex", f("logIndex"), "rootHash", "null", "treeSize", f("treeSize")),
		"hashes null":   obj("checkpoint", f("checkpoint"), "hashes", "null", "logIndex", f("logIndex"), "rootHash", f("rootHash"), "treeSize", f("treeSize")),
		"hashes a string": obj("checkpoint", f("checkpoint"), "hashes", `"`+strings.Repeat("00", 32)+`"`, "logIndex", f("logIndex"),
			"rootHash", f("rootHash"), "treeSize", f("treeSize")),
		"checkpoint null":      obj("checkpoint", "null", "hashes", f("hashes"), "logIndex", f("logIndex"), "rootHash", f("rootHash"), "treeSize", f("treeSize")),
		"byte-order mark":      append([]byte{0xEF, 0xBB, 0xBF}, with()...),
		"not JSON":             []byte(`checkpoint`),
		"a JSON string":        []byte(`"proof"`),
		"an empty JSON object": []byte(`{}`),
	}
	lenientReadsGenuine := 0
	for name, proof := range cases {
		if _, _, err := verifyInclusion(e.CanonicalBody, proof, rk); err == nil {
			t.Errorf("%s: the proof verifies", name)
		}
		// What the decoder this replaces made of the same bytes.
		var old struct {
			Checkpoint string   `json:"checkpoint"`
			Hashes     []string `json:"hashes"`
			LogIndex   *int64   `json:"logIndex"`
			RootHash   string   `json:"rootHash"`
			TreeSize   *int64   `json:"treeSize"`
		}
		if json.NewDecoder(bytes.NewReader(proof)).Decode(&old) == nil && old.LogIndex != nil && old.TreeSize != nil &&
			`"`+old.RootHash+`"` == f("rootHash") && old.Checkpoint != "" && len(old.Hashes) > 0 {
			lenientReadsGenuine++
		}
	}
	// The measurement that makes this test worth having: a lenient decode
	// reads the genuine proof out of many of these byte strings.
	if lenientReadsGenuine < 10 {
		t.Errorf("only %d of the respellings are read as the genuine proof by a lenient decoder; the cases no longer measure the difference", lenientReadsGenuine)
	}
	t.Logf("%d respellings refused; a lenient decoder reads the genuine proof out of %d of them", len(cases), lenientReadsGenuine)

	// A key may be ABSENT: that stays the existing, named finding.
	noCheckpoint := obj("hashes", f("hashes"), "logIndex", f("logIndex"), "rootHash", f("rootHash"), "treeSize", f("treeSize"))
	if _, _, err := verifyInclusion(e.CanonicalBody, noCheckpoint, rk); err == nil || !strings.Contains(err.Error(), "no signed checkpoint") {
		t.Errorf("proof without a checkpoint: %v", err)
	}
	noSize := obj("checkpoint", f("checkpoint"), "hashes", f("hashes"), "logIndex", f("logIndex"), "rootHash", f("rootHash"))
	if _, _, err := verifyInclusion(e.CanonicalBody, noSize, rk); err == nil || !strings.Contains(err.Error(), "lacks logIndex, treeSize or rootHash") {
		t.Errorf("proof without a tree size: %v", err)
	}
}

// The same decoder serves audit roots: VerifyRekorBy with the audit key's
// name reaches verifyInclusion, so the strict reading is not specific to the
// certificate path.
func TestInclusionProofStrictOnEveryRekorPath(t *testing.T) {
	e, rk, key := synthEntry(t, 7, true)
	for _, signer := range []string{"witness", AuditRootSigner} {
		if _, err := VerifyRekorBy(e, rk, key, signer); err != nil {
			t.Fatalf("%s: the clean synthetic entry must verify: %v", signer, err)
		}
		bad := e
		bad.InclusionProof = []byte(strings.Replace(string(e.InclusionProof), `"rootHash":`, `"rootHash":"`+strings.Repeat("00", 32)+`","rootHash":`, 1))
		if bytes.Equal(bad.InclusionProof, e.InclusionProof) {
			t.Fatal("premise: the synthetic proof has a rootHash key to duplicate")
		}
		if _, err := VerifyRekorBy(bad, rk, key, signer); err == nil || !strings.Contains(err.Error(), "duplicate object key") {
			t.Errorf("%s: duplicate rootHash (wrong, then genuine): %v", signer, err)
		}
	}
}

// A REAL certificate of the production witness (the SDK's v3 fixture) stores
// Rekor's inclusionProof object verbatim. The strict decoder reads it, and
// what it reads is what the log signed: the stored checkpoint verifies under
// the pinned public-good key and names the proof's tree size and root.
func TestInclusionProofStrictReadsAProductionCertificate(t *testing.T) {
	raw, err := os.ReadFile("../verify/testdata/real-v3-cert.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var cert struct {
		Attestation struct {
			TransparencyLog struct {
				InclusionProof string `json:"inclusion_proof"`
			} `json:"transparency_log"`
		} `json:"attestation"`
	}
	if err := json.Unmarshal(raw, &cert); err != nil {
		t.Fatal(err)
	}
	proofJSON, err := base64.StdEncoding.DecodeString(cert.Attestation.TransparencyLog.InclusionProof)
	if err != nil || len(proofJSON) == 0 {
		t.Fatalf("fixture carries no stored inclusion proof: %v", err)
	}
	p, err := decodeInclusionProof(proofJSON)
	if err != nil {
		t.Fatalf("the production certificate's stored proof is refused by the strict decoder: %v", err)
	}
	if p.LogIndex == nil || p.TreeSize == nil || len(p.Hashes) == 0 || p.Checkpoint == "" {
		t.Fatalf("stored proof read incompletely: %+v", p)
	}
	rk, err := ParseRekorKeyPEM(RekorPublicGoodPEM)
	if err != nil {
		t.Fatal(err)
	}
	size, root, err := VerifyCheckpoint(p.Checkpoint, rk)
	if err != nil || size != uint64(*p.TreeSize) || hex.EncodeToString(root) != p.RootHash {
		t.Fatalf("the stored checkpoint does not verify or names another tree: size %d root %x err %v", size, root, err)
	}
}
