package verify

// The Ed25519 acceptance rule of the witness-only verifier, applied by this
// SDK's own code before the bytes reach crypto/ed25519.
//
// crypto/ed25519 computes the cofactorless equation and compares the
// ENCODING of R. By itself it accepts a small-order R (for example the
// identity, a signature made with nonce 0) and a small-order public key, and
// it decodes a non-canonical y (>= p) as y − p; other Ed25519 libraries
// refuse those inputs. The checks are therefore explicit here and never left
// to the library. math/big only, so the file builds on every Go version the
// module supports.

import (
	"crypto/ed25519"
	"encoding/hex"
	"math/big"
)

// ed25519SmallOrderY — the y coordinates (little-endian, top bit of byte 31
// cleared) of the Ed25519 points of small order, canonical and
// non-canonical (the libsodium blocklist): 0, 1, the two order-8 values,
// p−1, p, p+1. With the sign bit either way: the 8 canonical small-order
// encodings plus 6 non-canonical ones.
var ed25519SmallOrderY = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
}

var (
	edP    = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edL, _ = new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	edD    = new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), edP)), edP)
)

// littleEndian reads b as an unsigned little-endian integer.
func littleEndian(b []byte) *big.Int {
	r := make([]byte, len(b))
	for i := range b {
		r[len(b)-1-i] = b[i]
	}
	return new(big.Int).SetBytes(r)
}

// encodedY is the y coordinate of a 32-byte point encoding: the low 255 bits.
func encodedY(enc []byte) *big.Int {
	b := append([]byte{}, enc...)
	b[31] &= 0x7f
	return littleEndian(b)
}

// smallOrderEncoding: the encoding's y is one of the small-order y values.
func smallOrderEncoding(enc []byte) bool {
	y := append([]byte{}, enc...)
	y[31] &= 0x7f
	h := hex.EncodeToString(y)
	for _, s := range ed25519SmallOrderY {
		if h == s {
			return true
		}
	}
	return false
}

// canonicalCurvePoint: y < p, some x satisfies −x² + y² = 1 + d·x²·y², and
// the sign bit is clear when that x is 0.
func canonicalCurvePoint(enc []byte) bool {
	y := encodedY(enc)
	if y.Cmp(edP) >= 0 {
		return false
	}
	y2 := new(big.Int).Mod(new(big.Int).Mul(y, y), edP)
	u := new(big.Int).Mod(new(big.Int).Sub(y2, big.NewInt(1)), edP)
	v := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(edD, y2), big.NewInt(1)), edP)
	x2 := new(big.Int).Mod(new(big.Int).Mul(u, new(big.Int).ModInverse(v, edP)), edP)
	if x2.Sign() == 0 {
		return enc[31]&0x80 == 0
	}
	half := new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(1)), 1)
	return new(big.Int).Exp(x2, half, edP).Cmp(big.NewInt(1)) == 0
}

// ed25519KeyAcceptable: the public key (exactly 32 raw bytes, after
// normalisation) is not a small-order encoding and is the canonical encoding
// of a curve point.
func ed25519KeyAcceptable(raw []byte) bool {
	if len(raw) != ed25519.PublicKeySize {
		return false
	}
	return !smallOrderEncoding(raw) && canonicalCurvePoint(raw)
}

// ed25519SignatureEncodingAcceptable: a 64-byte signature R ‖ S with S < L
// (canonical S) and R the canonical encoding of a point (y < p) that is not
// of small order. Whether the signature VERIFIES is still crypto/ed25519's
// cofactorless equation.
func ed25519SignatureEncodingAcceptable(sig []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	if littleEndian(sig[32:]).Cmp(edL) >= 0 {
		return false
	}
	return encodedY(sig[:32]).Cmp(edP) < 0 && !smallOrderEncoding(sig[:32])
}
