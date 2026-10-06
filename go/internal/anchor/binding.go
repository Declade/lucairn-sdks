package anchor

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"time"
)

// Anchor binding v1 (T-1231 S2a; mirrors dual-sandbox-architecture
// services/veil-witness/internal/anchorbinding). For certificates anchored
// with binding v1 the witness timestamps and logs
//
//	H = sha256("lucairn.anchor-binding/v1\n" || cert_hash || sha256(signable))
//
// where cert_hash is the digest the certificate records on
// attestation.timestamp.cert_hash and signable is the canonical JSON its
// witness signature covers. The RFC 3161 imprint is H; the Rekor hashedrekord
// entry logs sha512(H). The certificate marks this with
// attestation.timestamp.hash_algorithm == HashAlgorithmV1.
const (
	HashAlgorithmV1     = "lucairn.anchor-binding/v1"
	HashAlgorithmLegacy = "SHA-256"
	bindingDomainV1     = "lucairn.anchor-binding/v1\n"
)

// BindingV1Cutover is the moment from which every certificate issued by the
// Lucairn-HOSTED witness carries binding-v1 anchors. A hosted certificate
// whose SIGNED issued_at is after it and whose anchors are not binding v1 is
// TAMPERED (downgrade guard: the binding marker is unsigned, so stripping it
// must not turn a content-bound certificate into a merely genuine one).
//
// ⚑ PLACEHOLDER — FINALISE AT THE BOX WINDOW. It must be a moment AFTER the
// binding-v1 witness is live on the hosted box (certificates issued by the
// old witness after this moment would read TAMPERED). Certificates issued
// between the deploy and this moment are still recognised as content-bound
// when their anchors match H. Keep it equal to the website's
// ANCHOR_BINDING_CUTOVER (src/lib/evidence-bundle/anchor-binding.ts).
var BindingV1Cutover = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

// DigestV1 is H for a recorded cert_hash and a signed canonical signable.
func DigestV1(certHash, signable []byte) []byte {
	sh := sha256.Sum256(signable)
	h := sha256.New()
	h.Write([]byte(bindingDomainV1))
	h.Write(certHash)
	h.Write(sh[:])
	return h.Sum(nil)
}

// RekorDigestV1 is the SHA-512 digest (hex) a binding-v1 Rekor entry logs.
func RekorDigestV1(h []byte) string {
	d := sha512.Sum512(h)
	return hex.EncodeToString(d[:])
}
