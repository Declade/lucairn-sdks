package bundle_test

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/anchor"
	"github.com/declade/lucairn-sdks/go/internal/bundle"
	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

// goldenVectorsSHA256 pins the vendored copy of the audit service's golden
// vectors (dual-sandbox-architecture services/audit/testdata/
// s2b-golden-vectors.json; specs/2026-10/evidence/t1231-s2b/). The file is
// the shared merge gate of every implementation of the S2b byte rules — the
// audit service on main, its port on the pilot lineage, and this tool. If a
// vector does not reproduce here, the CODE is wrong (or the vectors moved):
// never edit the file to make this test pass.
const goldenVectorsSHA256 = "73d62a842894fb74331b7113b1d7668c7589e45286cb97f7d118fa3597e08bd0"

type goldenVectors struct {
	Format string `json:"format"`
	Rows   []struct {
		Kind              string `json:"kind"`
		PreviousEventHash string `json:"previous_event_hash"`
		EventID           string `json:"event_id"`
		EventType         string `json:"event_type"`
		SourceService     string `json:"source_service"`
		Actor             string `json:"actor"`
		PayloadUTF8       string `json:"payload_utf8"`
		PayloadSHA256     string `json:"payload_sha256"`
		RequestID         string `json:"request_id"`
		ConversationID    string `json:"conversation_id"`
		ConvSeq           uint64 `json:"conv_seq"`
		SerializedUTF8    string `json:"serialized_utf8"`
		EventHash         string `json:"event_hash"`
		LeafHash          string `json:"leaf_hash"`
	} `json:"rows"`
	RootsBySize     []string `json:"roots_by_size"`
	InclusionProofs []struct {
		LeafIndex uint64   `json:"leaf_index"`
		TreeSize  uint64   `json:"tree_size"`
		LeafHash  string   `json:"leaf_hash"`
		Path      []string `json:"path"`
		Root      string   `json:"root"`
	} `json:"inclusion_proofs"`
	RootArtifact struct {
		TreeSize     uint64 `json:"tree_size"`
		RootHash     string `json:"root_hash"`
		ArtifactUTF8 string `json:"artifact_utf8"`
		ArtifactHex  string `json:"artifact_hex"`
		SHA512       string `json:"sha512"`
	} `json:"root_artifact"`
	SignedRoot struct {
		SeedHex      string `json:"test_only_seed_hex"`
		PublicKeyHex string `json:"public_key_hex"`
		Scheme       string `json:"signature_scheme"`
		SignatureHex string `json:"signature_hex"`
		BodyUTF8     string `json:"hashedrekord_body_utf8"`
	} `json:"signed_root"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("golden vectors: %q is not hex", s)
	}
	return b
}

// TestS2bGoldenVectors reproduces every vector byte for byte with the code
// the tool verifies bundles with: the v2 event hash (bundle.EventHashV2), the
// leaf hash (anchor.AuditLeafHash), inclusion at two tree sizes
// (anchor.AuditInclusionRoot), the root artifact and its SHA-512
// (anchor.AuditRootArtifact / ParseAuditRootArtifact) and the signed root
// (anchor.VerifyAuditRoot, with the vector's hashedrekord body logged in a
// synthetic Rekor). The v1 row hash and the tree roots are not computed by
// the tool; they are reproduced here from the rules the file states (v1 by
// the stated serialisation, the roots by two independent tree builders), so
// that the leaves and roots the tool is checked against are themselves
// checked.
func TestS2bGoldenVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/s2b-golden-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); hex.EncodeToString(sum[:]) != goldenVectorsSHA256 {
		t.Fatalf("testdata/s2b-golden-vectors.json is not the pinned file (sha256 %x)", sum)
	}
	var g goldenVectors
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if g.Format != "lucairn.audit-s2b-golden/v1" || len(g.Rows) != 5 || len(g.RootsBySize) != 5 || len(g.InclusionProofs) < 4 {
		t.Fatalf("unexpected golden file: format %q, %d rows, %d roots, %d proofs", g.Format, len(g.Rows), len(g.RootsBySize), len(g.InclusionProofs))
	}

	lp := func(s string) string { return strconv.Itoa(len(s)) + ":" + s }
	leaves := make([][]byte, len(g.Rows))
	v1, v2 := 0, 0
	for i, r := range g.Rows {
		var got string
		switch r.Kind {
		case "v2":
			v2++
			e := bundle.AuditEvent{ConvSeq: r.ConvSeq, ConversationID: r.ConversationID, RequestID: r.RequestID, EventID: r.EventID,
				EventType: r.EventType, SourceService: r.SourceService, Actor: r.Actor, PayloadSHA256: r.PayloadSHA256, PreviousEventHash: r.PreviousEventHash}
			got = bundle.EventHashV2(e)
			if p := sha256.Sum256([]byte(r.PayloadUTF8)); hex.EncodeToString(p[:]) != r.PayloadSHA256 {
				t.Errorf("row %d: payload_sha256 is not sha256 of the payload", i)
			}
			want := bundle.EventHashV2Domain + lp(r.EventID) + lp(r.EventType) + lp(r.SourceService) + lp(r.Actor) +
				lp(r.PayloadSHA256) + lp(r.RequestID) + lp(r.ConversationID) + lp(strconv.FormatUint(r.ConvSeq, 10))
			if want != r.SerializedUTF8 {
				t.Errorf("row %d: v2 serialisation differs from the vector:\n got %q\nwant %q", i, want, r.SerializedUTF8)
			}
		case "v1":
			v1++
			ser := lp(r.EventID) + lp(r.EventType) + lp(r.SourceService) + lp(r.Actor) + lp(r.PayloadUTF8)
			if ser != r.SerializedUTF8 {
				t.Errorf("row %d: v1 serialisation differs from the vector:\n got %q\nwant %q", i, ser, r.SerializedUTF8)
			}
			h := sha256.Sum256([]byte(r.PreviousEventHash + ser))
			got = hex.EncodeToString(h[:])
		default:
			t.Fatalf("row %d: unknown kind %q", i, r.Kind)
		}
		if got != r.EventHash {
			t.Errorf("row %d (%s): event_hash %s, vector %s", i, r.Kind, got, r.EventHash)
		}
		if i > 0 && r.PreviousEventHash != g.Rows[i-1].EventHash {
			t.Errorf("row %d: previous_event_hash is not row %d's event_hash", i, i-1)
		}
		leaves[i] = anchor.AuditLeafHash(r.EventHash)
		if hex.EncodeToString(leaves[i]) != r.LeafHash {
			t.Errorf("row %d: leaf hash %x, vector %s", i, leaves[i], r.LeafHash)
		}
	}
	if v1 == 0 || v2 == 0 {
		t.Fatalf("golden rows: %d v1, %d v2 — both kinds are required", v1, v2)
	}

	for n := 1; n <= len(leaves); n++ {
		levels := bundletest.AuditTreeLevels(leaves[:n])
		if got := hex.EncodeToString(levels[len(levels)-1][0]); got != g.RootsBySize[n-1] {
			t.Errorf("tree size %d: level-by-level root %s, vector %s", n, got, g.RootsBySize[n-1])
		}
		if got := hex.EncodeToString(bundletest.RFC6962Root(leaves[:n])); got != g.RootsBySize[n-1] {
			t.Errorf("tree size %d: RFC 6962 root %s, vector %s", n, got, g.RootsBySize[n-1])
		}
	}

	sizes := map[uint64]bool{}
	for i, p := range g.InclusionProofs {
		sizes[p.TreeSize] = true
		path := make([][]byte, len(p.Path))
		for j, h := range p.Path {
			path[j] = mustHex(t, h)
		}
		if p.LeafHash != g.Rows[p.LeafIndex].LeafHash || p.Root != g.RootsBySize[p.TreeSize-1] {
			t.Errorf("proof %d: its leaf or root is not the row's / the tree's", i)
		}
		got, err := anchor.AuditInclusionRoot(p.LeafIndex, p.TreeSize, g.Rows[p.LeafIndex].EventHash, path)
		if err != nil || hex.EncodeToString(got) != p.Root {
			t.Errorf("proof %d (leaf %d, size %d): root %x (%v), vector %s", i, p.LeafIndex, p.TreeSize, got, err, p.Root)
		}
		// The vector's path is exactly the path either tree builder produces.
		levels := bundletest.AuditTreeLevels(leaves[:p.TreeSize])
		for name, built := range map[string][][]byte{
			"level-by-level": bundletest.AuditTreePath(levels, p.LeafIndex),
			"RFC 6962":       bundletest.RFC6962Path(int(p.LeafIndex), leaves[:p.TreeSize]),
		} {
			if len(built) != len(path) {
				t.Errorf("proof %d: %s path has %d elements, vector %d", i, name, len(built), len(path))
				continue
			}
			for j := range built {
				if !bytes.Equal(built[j], path[j]) {
					t.Errorf("proof %d: %s path element %d differs from the vector", i, name, j)
				}
			}
		}
	}
	if len(sizes) < 2 {
		t.Fatalf("golden proofs cover %d tree size(s), want at least two", len(sizes))
	}

	ra := g.RootArtifact
	artifact := anchor.AuditRootArtifact(ra.TreeSize, mustHex(t, ra.RootHash))
	if string(artifact) != ra.ArtifactUTF8 || hex.EncodeToString(artifact) != ra.ArtifactHex {
		t.Errorf("root artifact %q, vector %q", artifact, ra.ArtifactUTF8)
	}
	if ra.RootHash != g.RootsBySize[ra.TreeSize-1] {
		t.Errorf("root artifact names a root that is not the tree's at size %d", ra.TreeSize)
	}
	digest := sha512.Sum512(artifact)
	if hex.EncodeToString(digest[:]) != ra.SHA512 {
		t.Errorf("sha512(artifact) %x, vector %s", digest, ra.SHA512)
	}
	if size, root, err := anchor.ParseAuditRootArtifact([]byte(ra.ArtifactUTF8)); err != nil || size != ra.TreeSize || hex.EncodeToString(root) != ra.RootHash {
		t.Errorf("parsing the vector's artifact: size %d root %x err %v", size, root, err)
	}

	sr := g.SignedRoot
	if sr.Scheme != "Ed25519ph" {
		t.Fatalf("signature scheme %q", sr.Scheme)
	}
	priv := ed25519.NewKeyFromSeed(mustHex(t, sr.SeedHex)) // a fixed PUBLIC test seed, see the file's note
	pub := priv.Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != sr.PublicKeyHex {
		t.Errorf("public key %x, vector %s", pub, sr.PublicKeyHex)
	}
	sig, err := priv.Sign(nil, digest[:], crypto.SHA512)
	if err != nil || hex.EncodeToString(sig) != sr.SignatureHex {
		t.Errorf("Ed25519ph signature %x (%v), vector %s", sig, err, sr.SignatureHex)
	}
	// The whole root check the tool runs, on the vector's signature and the
	// vector's hashedrekord body (logged in a synthetic Rekor), under the
	// vector's key as the pinned audit key.
	w, err := bundletest.NewWorld("golden")
	if err != nil {
		t.Fatal(err)
	}
	entry, err := w.LogBody([]byte(sr.BodyUTF8), time.Date(2026, 10, 6, 20, 0, 0, 0, time.UTC), 700001)
	if err != nil {
		t.Fatal(err)
	}
	root := anchor.AuditRoot{Artifact: []byte(ra.ArtifactUTF8), Signature: mustHex(t, sr.SignatureHex), Entry: entry}
	res, err := anchor.VerifyAuditRoot(root, w.Roots().Rekor, pub)
	if err != nil || res.TreeSize != ra.TreeSize || hex.EncodeToString(res.Root) != ra.RootHash {
		t.Fatalf("VerifyAuditRoot on the golden signed root: %+v %v", res, err)
	}
	if _, err := anchor.VerifyAuditRoot(root, w.Roots().Rekor, w.Roots().ServiceKeys[bundletest.AuditService]); err == nil {
		t.Error("the golden signed root verifies under another audit key")
	}
}
