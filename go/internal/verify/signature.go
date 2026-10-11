package verify

import (
	"crypto/ed25519"
)

// VerifyEd25519 returns true on valid signature, false on invalid.
// Returns a normalization error if publicKey is malformed; the caller
// wraps it as a CertificateError with ReasonInvalidSignature.
//
// The acceptance rule is the chain verifier's (chain_keys.go), called here
// rather than copied, so the witness-only path and the chain path cannot
// drift and the result does not depend on what crypto/ed25519 accepts by
// itself. Each of these returns (false, nil) — an invalid signature:
//   - a public key whose 32 raw bytes are a small-order encoding or are not
//     the canonical encoding of a curve point;
//   - a signature that is not 64 bytes R ‖ S, has S >= L, or whose R is a
//     non-canonical encoding (y >= p) or a small-order point.
//
// The chain verifier's refusal of the published parity-corpus test keys is a
// pinned-key-set policy and is deliberately not applied here.
func VerifyEd25519(message, signature []byte, publicKey any) (bool, error) {
	raw, err := NormalizeEd25519PublicKey(publicKey)
	if err != nil {
		return false, err
	}
	if smallOrderEncoding(raw) || !canonicalCurvePoint(raw) {
		return false, nil
	}
	return chainStrictVerify(ed25519.PublicKey(raw), message, signature), nil
}
