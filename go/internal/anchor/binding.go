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
// Lucairn-HOSTED witness must carry binding-v1 anchors: 2026-11-01T00:00:00Z
// (final). A hosted certificate whose SIGNED issued_at is after it and whose
// timestamp does not declare binding v1 is TAMPERED (downgrade guard: the
// binding marker is unsigned, so stripping it must not turn a content-bound
// certificate into a merely genuine one).
//
// The hosted witness runs binding v1 before this moment, so certificates
// issued between that deploy and the cutover are already content-bound
// whenever their anchors match H; the cutover only arms the guard. The same
// literal is the website's ANCHOR_BINDING_CUTOVER
// (src/lib/evidence-bundle/anchor-binding.ts) and the hosted witness's
// WITNESS_ANCHOR_BINDING_REQUIRED_AFTER; TestBindingV1Cutover_FinalLiteral
// pins it.
var BindingV1Cutover = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

// BindingV1CutoverRFC3339 is BindingV1Cutover as published.
const BindingV1CutoverRFC3339 = "2026-11-01T00:00:00Z"

// CleaningCounterStartRFC3339 pins the hosted cleaning counter start.
// Custom witness deployments supply their own start, just as for binding.
const CleaningCounterStartRFC3339 = "2026-10-08T00:00:00Z"

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
