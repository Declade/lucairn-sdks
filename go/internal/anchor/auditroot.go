package anchor

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Audit roots (T-1231 S2b). The audit service keeps every audit row's
// event_hash in one append-only Merkle tree and, once an hour, signs the
// tree's root and logs that signature in Rekor. A bundle carries, per counted
// request, an inclusion path to the earliest such root that covers it.
//
// Design: specs/2026-10/design-2026-10-06-t1231-s2b-audit-counter.md §5–§6.

// AuditRootArtifactPrefix is the domain tag of the signed root artifact.
const AuditRootArtifactPrefix = "lucairn.audit-root/v1\n"

// AuditRootSigner is the service id of the key that signs audit roots: the
// audit service's existing claim-signing key (design D5). The tool always
// takes this pinned key — never a key or key id named by the bundle.
const AuditRootSigner = "dsa-audit"

// MaxAuditProofHashes bounds an inclusion path (a tree of 2^64 leaves needs
// at most 64 siblings).
const MaxAuditProofHashes = 64

// AuditRootArtifact is the exact byte string the audit service signs and
// whose SHA-512 it logs in Rekor:
//
//	"lucairn.audit-root/v1\n" + decimal(tree_size) + "\n" + hex(root) + "\n"
func AuditRootArtifact(treeSize uint64, root []byte) []byte {
	return []byte(AuditRootArtifactPrefix + strconv.FormatUint(treeSize, 10) + "\n" + hex.EncodeToString(root) + "\n")
}

// ParseAuditRootArtifact reads tree size and root out of a root artifact. It
// accepts exactly the one canonical spelling (no sign, no leading zero,
// lowercase hex, one trailing newline, nothing after it): the parsed values
// re-serialise to the same bytes, so two different byte strings can never
// mean the same root.
func ParseAuditRootArtifact(b []byte) (uint64, []byte, error) {
	if !bytes.HasPrefix(b, []byte(AuditRootArtifactPrefix)) {
		return 0, nil, errors.New("root artifact does not start with the lucairn.audit-root/v1 tag")
	}
	parts := strings.Split(string(b[len(AuditRootArtifactPrefix):]), "\n")
	if len(parts) != 3 || parts[2] != "" {
		return 0, nil, errors.New("root artifact is not tag, tree size and root hash on three lines")
	}
	size, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || size == 0 {
		return 0, nil, errors.New("root artifact tree size is not a positive decimal number")
	}
	root, err := hex.DecodeString(parts[1])
	if err != nil || len(root) != sha256.Size {
		return 0, nil, errors.New("root artifact root hash is not 32 hex bytes")
	}
	if !bytes.Equal(AuditRootArtifact(size, root), b) {
		return 0, nil, errors.New("root artifact is not in its canonical spelling")
	}
	return size, root, nil
}

// AuditLeafHash is the audit tree's leaf for one audit row: the RFC 6962 leaf
// hash of the row's event_hash AS ITS 64 ASCII HEX CHARACTERS (not the 32
// decoded bytes) — sha256(0x00 || []byte(event_hash_hex)).
func AuditLeafHash(eventHashHex string) []byte {
	h := sha256.Sum256(append([]byte{0x00}, eventHashHex...))
	return h[:]
}

// AuditInclusionRoot returns the root that a row's event_hash and its audit
// path imply for the leaf at leafIndex in a tree of treeSize leaves, by the
// index/size-bound algorithm of RFC 9162 § 2.1.3.2: index and size decide at
// every step on which side the sibling goes, and a path that is too long or
// too short for that size is an error. No left/right flag from the bundle is
// ever read — a flag supplied with the proof would let the prover choose the
// leaf's position.
func AuditInclusionRoot(leafIndex, treeSize uint64, eventHashHex string, path [][]byte) ([]byte, error) {
	if treeSize == 0 || leafIndex >= treeSize {
		return nil, fmt.Errorf("leaf index %d is outside a tree of %d leaves", leafIndex, treeSize)
	}
	if len(path) > MaxAuditProofHashes {
		return nil, errors.New("inclusion proof is longer than any tree allows")
	}
	for i, p := range path {
		if len(p) != sha256.Size {
			return nil, fmt.Errorf("inclusion proof hash %d is not 32 bytes", i)
		}
	}
	return rootFromInclusionProof(leafIndex, treeSize, AuditLeafHash(eventHashHex), path)
}

// AuditRoot is one anchored root as a bundle carries it.
type AuditRoot struct {
	// Artifact is the exact signed byte string (AuditRootArtifact).
	Artifact []byte
	// Signature is the audit service's Ed25519ph signature over
	// sha512(Artifact).
	Signature []byte
	// Entry is the Rekor entry that logs sha512(Artifact).
	Entry RekorEntry
}

// AuditRootResult is what a verified root states.
type AuditRootResult struct {
	TreeSize uint64
	Root     []byte
	// IntegratedTime is when Rekor logged the root: every row under it
	// existed by then.
	IntegratedTime time.Time
	LogIndex       int64
}

// VerifyAuditRoot verifies one anchored audit root offline:
//
//  1. the artifact is a canonical lucairn.audit-root/v1 artifact;
//  2. the root signature is a valid Ed25519ph signature over sha512(artifact)
//     under the PINNED audit key (auditKey) — not a key the bundle names;
//  3. the Rekor entry verifies exactly like a certificate's (VerifyRekor:
//     signed entry timestamp, inclusion proof, REQUIRED signed checkpoint,
//     hashedrekord body) with the pinned audit key in the witness key's
//     place, i.e. the audit key itself logged the digest;
//  4. the digest the entry logs is sha512(artifact).
func VerifyAuditRoot(r AuditRoot, rk *RekorKey, auditKey ed25519.PublicKey) (*AuditRootResult, error) {
	if len(auditKey) != ed25519.PublicKeySize {
		return nil, errors.New("no " + AuditRootSigner + " key pinned")
	}
	size, root, err := ParseAuditRootArtifact(r.Artifact)
	if err != nil {
		return nil, err
	}
	digest := sha512.Sum512(r.Artifact)
	if len(r.Signature) != ed25519.SignatureSize ||
		ed25519.VerifyWithOptions(auditKey, digest[:], r.Signature, &ed25519.Options{Hash: crypto.SHA512}) != nil {
		return nil, errors.New("the root signature does not verify under the pinned " + AuditRootSigner + " key")
	}
	res, err := VerifyRekorBy(r.Entry, rk, auditKey, AuditRootSigner)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(res.ArtifactSHA512, hex.EncodeToString(digest[:])) {
		return nil, errors.New("the Rekor entry logs another artifact than this root (its digest is not sha512 of the root artifact)")
	}
	return &AuditRootResult{TreeSize: size, Root: root, IntegratedTime: res.IntegratedTime, LogIndex: r.Entry.LogIndex}, nil
}
