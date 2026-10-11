package verify

import (
	"crypto/ed25519"
)

// VerifyEd25519 returns true on valid signature, false on invalid.
// Returns a normalization error if publicKey is malformed; the caller
// wraps it as a CertificateError with ReasonInvalidSignature.
//
// Before crypto/ed25519 is called, this SDK's own rule (ed25519_rule.go) is
// applied to the 32 raw key bytes and to the signature bytes, so the result
// does not depend on what the library accepts by itself. Each of these
// returns (false, nil) — an invalid signature:
//   - a public key that is a small-order encoding or is not the canonical
//     encoding of a curve point;
//   - a signature that is not 64 bytes R ‖ S, has S >= L, or whose R is a
//     non-canonical encoding (y >= p) or a small-order point.
func VerifyEd25519(message, signature []byte, publicKey any) (bool, error) {
	raw, err := NormalizeEd25519PublicKey(publicKey)
	if err != nil {
		return false, err
	}
	if len(signature) != ed25519.SignatureSize {
		// ed25519.Verify returns false silently on wrong-length signatures;
		// surface the precondition explicitly so tests lock in the invariant.
		return false, nil
	}
	if !ed25519KeyAcceptable(raw) || !ed25519SignatureEncodingAcceptable(signature) {
		return false, nil
	}
	return ed25519.Verify(ed25519.PublicKey(raw), message, signature), nil
}
