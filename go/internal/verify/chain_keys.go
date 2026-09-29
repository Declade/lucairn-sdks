package verify

// Pinned-key policy and the ONE Ed25519 acceptance rule of the certificate
// chain recipe (parity corpus spec § Pinned keys, § Signatures). The TS and
// Python SDKs refuse the same keys and accept the same signatures; the
// vendored key-policy.json vectors and the corpus cases hold all three to it.
// The witness-signature-only VerifyCertificate path (signature.go, keys.go)
// is unchanged.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"math/big"
)

// Key-policy codes, checked in this order. A refused key is a caller error,
// never a verdict.
const (
	KeyPolicyOK           = "ok"
	KeyPolicyMalformed    = "key_malformed"
	KeyPolicySmallOrder   = "key_small_order"
	KeyPolicyInvalidPoint = "key_invalid_point"
	KeyPolicyTestKey      = "key_test_key"
)

// ChainTestKeys are the public keys of the parity corpus (witness, the seven
// pinned services, and the two keys that sign its unpinned / rogue tamper
// cases), standard base64. The corpus seed is public, so their private keys
// are too: a verifier refuses them unless the caller sets AllowTestKeys,
// which only a parity harness does. parity_corpus_test.go checks this list
// against the vendored keys.json.
var ChainTestKeys = []string{
	"DADdf3OIOXxhBl2VQ5k1Kk8VgCTNBVhrWolquUvskSc=", // witness_parity_v1
	"CEYOK2jlNGFq+qO34Lsv1J683D6o0xP7/zh8CExSEPw=", // dsa-ai
	"g34bEFHw7VjKYrRbblIGfjR7vktJDyqrf5xJfLHTyJE=", // dsa-audit
	"l4pxgBHACNYoETbJISAgKf2GFv32LsF44RZ+5CXsbmk=", // dsa-bridge
	"QfwIjbzb5aYQsBsrp+1dhyh5XeO/wRokwWcQxfgvSc8=", // dsa-gateway
	"ufi3DjW9XlboFkOiQiDHRFZpDFpvPgxZCw516lNr7Kg=", // dsa-reid-guard
	"tS+sf+14i1H/qJLJcrNvIvg2B5iJQ2KMXQhirCKsKLs=", // dsa-sanitizer
	"XF4RayFQtg/k+NkMnsSnlrA/mEgv63vRzi6GKrSSQzY=", // dsa-sanitizer-streaming
	"/eReR5ZWs84YMcnJkk7lNr1iOetpZXTaPIy/EERjio0=", // not pinned: dsa-unpinned
	"9oGMdHYHc5/aVzMjYZkLNdXqKsNR1A5aNp8bmSdd1Aw=", // not pinned: rogue
}

var chainTestKeySet = func() map[string]bool {
	out := map[string]bool{}
	for _, k := range ChainTestKeys {
		raw, err := base64.StdEncoding.DecodeString(k)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			panic("verify: ChainTestKeys entry is not a 32-byte base64 key")
		}
		out[string(raw)] = true
	}
	return out
}()

// chainSmallOrderY — the y coordinates (little-endian, top bit of byte 31
// cleared) of the Ed25519 points of small order, canonical and
// non-canonical (the libsodium blocklist): 0, 1, the two order-8 values,
// p−1, p, p+1. With the sign bit either way: the 8 canonical small-order
// encodings plus 6 non-canonical ones.
var chainSmallOrderY = []string{
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
	for _, s := range chainSmallOrderY {
		if h == s {
			return true
		}
	}
	return false
}

// canonicalCurvePoint: y < p, some x satisfies −x² + y² = 1 + d·x²·y², and
// the sign bit is clear when that x is 0. crypto/ed25519 would decode a
// non-canonical y (≥ p) as y − p, which libsodium refuses.
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

// PinnedChainKey applies the pinned-key policy to one key. A key given as
// text must be canonical standard padded base64 (decode, re-encode, compare)
// of exactly 32 bytes; a key given as []byte must be exactly 32 bytes; any
// other input is malformed. Then: not a small-order encoding, the canonical
// encoding of a curve point, and not a parity-corpus test key unless
// allowTestKeys. Returns the key and KeyPolicyOK, or nil and the code.
func PinnedChainKey(input any, allowTestKeys bool) (ed25519.PublicKey, string) {
	var raw []byte
	switch v := input.(type) {
	case string:
		b, ok := chainB64(v)
		if v == "" || !ok {
			return nil, KeyPolicyMalformed
		}
		raw = b
	case []byte:
		raw = append([]byte{}, v...)
	case ed25519.PublicKey:
		raw = append([]byte{}, v...)
	default:
		return nil, KeyPolicyMalformed
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, KeyPolicyMalformed
	}
	if smallOrderEncoding(raw) {
		return nil, KeyPolicySmallOrder
	}
	if !canonicalCurvePoint(raw) {
		return nil, KeyPolicyInvalidPoint
	}
	if !allowTestKeys && chainTestKeySet[string(raw)] {
		return nil, KeyPolicyTestKey
	}
	return ed25519.PublicKey(raw), KeyPolicyOK
}

// chainStrictVerify is the ONE Ed25519 acceptance rule: a 64-byte signature
// R ‖ S with S < L (canonical S), R the canonical encoding of a point (y < p)
// that is not of small order, and the cofactorless equation compared as the
// encoding of R (crypto/ed25519.Verify). Go's crypto/ed25519 accepts a
// small-order R by itself (libsodium refuses it), hence the explicit
// pre-checks. The key passed PinnedChainKey at load.
func chainStrictVerify(pub ed25519.PublicKey, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	if littleEndian(sig[32:]).Cmp(edL) >= 0 {
		return false
	}
	if encodedY(sig[:32]).Cmp(edP) >= 0 || smallOrderEncoding(sig[:32]) {
		return false
	}
	return ed25519.Verify(pub, msg, sig)
}
