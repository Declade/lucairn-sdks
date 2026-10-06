package anchor_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/declade/lucairn-sdks/go/internal/anchor"
	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

func eventHash(i int) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("synthetic audit row %d", i)))
	return hex.EncodeToString(h[:])
}

// TestAuditTreeEqualsRFC6962 pins the claim the S2b design only ARGUED: the
// audit service's tree (built level by level, an odd node promoted
// unchanged) is the RFC 6962 tree (split at the largest power of two below
// n) for every size, its audit paths are the RFC 6962 audit paths, and the
// tool's index/size-bound verifier (RFC 9162 section 2.1.3.2) accepts
// exactly them. Three independent pieces of code: the level-by-level builder
// (bundletest.AuditTreeLevels, a port of the audit service's), the RFC
// recursion (bundletest.RFC6962Root / RFC6962Path) and the verifier
// (anchor.AuditInclusionRoot).
func TestAuditTreeEqualsRFC6962(t *testing.T) {
	const max = 260
	hashes := make([]string, max)
	leaves := make([][]byte, max)
	for i := range hashes {
		hashes[i] = eventHash(i)
		leaves[i] = anchor.AuditLeafHash(hashes[i])
	}
	for n := 1; n <= max; n++ {
		levels := bundletest.AuditTreeLevels(leaves[:n])
		root := levels[len(levels)-1][0]
		if rfc := bundletest.RFC6962Root(leaves[:n]); !bytes.Equal(root, rfc) {
			t.Fatalf("size %d: level-by-level root != RFC 6962 root", n)
		}
		for i := 0; i < n; i++ {
			path := bundletest.AuditTreePath(levels, uint64(i))
			rfcPath := bundletest.RFC6962Path(i, leaves[:n])
			if len(path) != len(rfcPath) {
				t.Fatalf("size %d leaf %d: path length %d != RFC %d", n, i, len(path), len(rfcPath))
			}
			for k := range path {
				if !bytes.Equal(path[k], rfcPath[k]) {
					t.Fatalf("size %d leaf %d: path element %d differs from the RFC 6962 audit path", n, i, k)
				}
			}
			got, err := anchor.AuditInclusionRoot(uint64(i), uint64(n), hashes[i], path)
			if err != nil || !bytes.Equal(got, root) {
				t.Fatalf("size %d leaf %d: verifier does not reproduce the root (%v)", n, i, err)
			}
			// The same path must NOT prove another position or another row.
			if n > 1 {
				j := (i + 1) % n
				if got, err := anchor.AuditInclusionRoot(uint64(j), uint64(n), hashes[i], path); err == nil && bytes.Equal(got, root) {
					t.Fatalf("size %d: leaf %d's path also verifies at index %d", n, i, j)
				}
				if got, err := anchor.AuditInclusionRoot(uint64(i), uint64(n), hashes[j], path); err == nil && bytes.Equal(got, root) {
					t.Fatalf("size %d: leaf %d's path also verifies for row %d", n, i, j)
				}
			}
		}
	}
}

func TestAuditInclusionRootRejectsMalformedProofs(t *testing.T) {
	hashes := make([]string, 11)
	leaves := make([][]byte, 11)
	for i := range hashes {
		hashes[i] = eventHash(i)
		leaves[i] = anchor.AuditLeafHash(hashes[i])
	}
	levels := bundletest.AuditTreeLevels(leaves)
	root := levels[len(levels)-1][0]
	path := bundletest.AuditTreePath(levels, 6)
	ok := func(idx, size uint64, p [][]byte) bool {
		got, err := anchor.AuditInclusionRoot(idx, size, hashes[6], p)
		return err == nil && bytes.Equal(got, root)
	}
	if !ok(6, 11, path) {
		t.Fatal("genuine proof rejected")
	}
	cases := map[string]bool{
		"index == size": ok(11, 11, path),
		"size 0":        ok(0, 0, nil),
		// (A size with the same path shape for this leaf, e.g. 12, walks the
		// same hashes: the tree size is authenticated by the SIGNED root
		// artifact, which names it, not by the path.)
		"smaller size":    ok(6, 7, path),
		"much larger":     ok(6, 1<<20, path),
		"path too long":   ok(6, 11, append(append([][]byte{}, path...), leaves[0])),
		"path too short":  ok(6, 11, path[:len(path)-1]),
		"path reordered":  ok(6, 11, [][]byte{path[1], path[0], path[2], path[3]}),
		"31-byte sibling": ok(6, 11, append([][]byte{path[0][:31]}, path[1:]...)),
		"65 siblings":     ok(6, 11, make([][]byte, 65)),
	}
	for name, accepted := range cases {
		if accepted {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Independent vectors (Python hashlib): the leaf is over the event_hash's 64
// hex CHARACTERS, and the root artifact is the three-line byte string.
func TestAuditLeafAndArtifactVectors(t *testing.T) {
	const eh = "4f8efac874f2b7801b8dd76c9a0b20bc01495027f2b720b555b189e8bf61f7c1"
	if got := hex.EncodeToString(anchor.AuditLeafHash(eh)); got != "4d0cbfb044c27e3b56267371cb5b047e9db196634fe8bf920b5faadc2eca8d95" {
		t.Fatalf("leaf hash %s", got)
	}
	root := bytes.Repeat([]byte{0x11}, 32)
	art := anchor.AuditRootArtifact(57, root)
	if string(art) != "lucairn.audit-root/v1\n57\n"+strings.Repeat("11", 32)+"\n" {
		t.Fatalf("artifact %q", art)
	}
	size, r, err := anchor.ParseAuditRootArtifact(art)
	if err != nil || size != 57 || !bytes.Equal(r, root) {
		t.Fatalf("round trip: %d %x %v", size, r, err)
	}
}

func TestParseAuditRootArtifactIsStrict(t *testing.T) {
	h := strings.Repeat("ab", 32)
	for name, s := range map[string]string{
		"leading zero":        "lucairn.audit-root/v1\n057\n" + h + "\n",
		"plus sign":           "lucairn.audit-root/v1\n+57\n" + h + "\n",
		"size zero":           "lucairn.audit-root/v1\n0\n" + h + "\n",
		"negative":            "lucairn.audit-root/v1\n-1\n" + h + "\n",
		"uppercase hex":       "lucairn.audit-root/v1\n57\n" + strings.ToUpper(h) + "\n",
		"no trailing newline": "lucairn.audit-root/v1\n57\n" + h,
		"trailing data":       "lucairn.audit-root/v1\n57\n" + h + "\nx",
		"extra newline":       "lucairn.audit-root/v1\n57\n" + h + "\n\n",
		"CRLF":                "lucairn.audit-root/v1\r\n57\r\n" + h + "\r\n",
		"other tag":           "lucairn.audit-root/v2\n57\n" + h + "\n",
		"claim-like bytes":    `{"claim_id":"x"}`,
		"31-byte root":        "lucairn.audit-root/v1\n57\n" + h[:62] + "\n",
		"space in size":       "lucairn.audit-root/v1\n57 \n" + h + "\n",
		"empty":               "",
	} {
		if _, _, err := anchor.ParseAuditRootArtifact([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// VerifyAuditRoot: the pinned audit key and nothing else.
func TestVerifyAuditRootPinsTheAuditKey(t *testing.T) {
	w, err := bundletest.NewWorld("audit-root")
	if err != nil {
		t.Fatal(err)
	}
	sc, err := w.NewAuditScenario(bundletest.ScenarioOptions{})
	if err != nil {
		t.Fatal(err)
	}
	roots := w.Roots()
	audit := roots.ServiceKeys[bundletest.AuditService]
	for i, r := range sc.Evidence.Roots {
		ar := bundletest.AnchorRoot(r)
		res, err := anchor.VerifyAuditRoot(ar, roots.Rekor, audit)
		if err != nil || res.TreeSize != r.TreeSize || !bytes.Equal(res.Root, r.Root) {
			t.Fatalf("root %d: %v", i, err)
		}
		for name, key := range map[string]ed25519.PublicKey{
			"witness key": w.Witness.Public().(ed25519.PublicKey), "bridge key": roots.ServiceKeys["dsa-bridge"], "no key": nil,
		} {
			if _, err := anchor.VerifyAuditRoot(ar, roots.Rekor, key); err == nil {
				t.Errorf("root %d verifies under the %s", i, name)
			}
		}
		// A certificate anchor's verifier must not accept an audit-root entry
		// as a witness entry either.
		if _, err := anchor.VerifyRekor(ar.Entry, roots.Rekor, w.Witness.Public().(ed25519.PublicKey)); err == nil {
			t.Errorf("root %d: its Rekor entry verifies as a witness entry", i)
		}
		bad := ar
		bad.Signature = append([]byte(nil), ar.Signature...)
		bad.Signature[5] ^= 1
		if _, err := anchor.VerifyAuditRoot(bad, roots.Rekor, audit); err == nil {
			t.Errorf("root %d: flipped signature accepted", i)
		}
		// A plain (not pre-hashed) Ed25519 signature over the artifact is not
		// a root signature: claims are plain Ed25519, roots are Ed25519ph.
		plain := ar
		plain.Signature = ed25519.Sign(w.Services[bundletest.AuditService], ar.Artifact)
		if _, err := anchor.VerifyAuditRoot(plain, roots.Rekor, audit); err == nil {
			t.Errorf("root %d: plain Ed25519 signature accepted as a root signature", i)
		}
	}
	if _, err := anchor.VerifyAuditRoot(bundletest.AnchorRoot(sc.ForgedR1), roots.Rekor, audit); err == nil {
		t.Error("root signed and logged by another key accepted")
	}
	if _, err := anchor.VerifyAuditRoot(bundletest.AnchorRoot(sc.MixedR1), roots.Rekor, audit); err == nil || !strings.Contains(err.Error(), "not logged by the pinned dsa-audit key") {
		t.Errorf("root whose Rekor entry another key made: %v", err)
	}
}
