package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The witness-only primitive (VerifyEd25519) applies the chain verifier's
// acceptance rule by its own code: a small-order R, a small-order or
// non-canonical public key and S >= L are refused, whatever crypto/ed25519
// accepts by itself. Every assertion here is a refusal (or an honest
// signature verifying).

// sigRuleVectors reads the 14 small-order encodings and the invalid-point
// keys from the vendored key-policy vectors (not from the code under test).
func sigRuleVectors(t *testing.T) (smallOrder, invalidPoints [][]byte) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "parity-corpus", "v1", "key-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var kp struct {
		Vectors []struct {
			ID        string `json:"id"`
			PublicKey string `json:"public_key"`
			Expected  string `json:"expected"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(b, &kp); err != nil {
		t.Fatal(err)
	}
	small := regexp.MustCompile(`^small_order_\d\d_`)
	seen := map[string]bool{}
	for _, v := range kp.Vectors {
		raw, err := base64.StdEncoding.DecodeString(v.PublicKey)
		switch {
		case small.MatchString(v.ID):
			if err != nil || len(raw) != 32 {
				t.Fatalf("%s: not a 32-byte key", v.ID)
			}
			smallOrder = append(smallOrder, raw)
			seen[string(raw)] = true
		case strings.HasPrefix(v.ID, "invalid_point_") && v.Expected == KeyPolicyInvalidPoint:
			if err != nil || len(raw) != 32 {
				t.Fatalf("%s: not a 32-byte key", v.ID)
			}
			invalidPoints = append(invalidPoints, raw)
		}
	}
	if len(smallOrder) != 14 || len(seen) != 14 {
		t.Fatalf("%d small-order vectors (%d distinct), want 14", len(smallOrder), len(seen))
	}
	if len(invalidPoints) < 3 {
		t.Fatalf("%d invalid-point vectors", len(invalidPoints))
	}
	return smallOrder, invalidPoints
}

// sigRuleChallenge is k = SHA-512(R ‖ A ‖ M) mod L.
func sigRuleChallenge(r, a, m []byte) *big.Int {
	h := sha512.New()
	h.Write(r)
	h.Write(a)
	h.Write(m)
	return new(big.Int).Mod(littleEndian(h.Sum(nil)), edL)
}

// sigRuleLE32 is n as 32 little-endian bytes.
func sigRuleLE32(n *big.Int) []byte {
	be := n.Bytes()
	out := make([]byte, 32)
	for i := range be {
		out[i] = be[len(be)-1-i]
	}
	return out
}

// sigRuleKey is a fixed TEST key (seed = sha256 of a label) with its secret
// scalar.
func sigRuleKey() (ed25519.PublicKey, ed25519.PrivateKey, *big.Int) {
	seed := sha256.Sum256([]byte("lucairn-sdks go witness-only signature rule"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	h := sha512.Sum512(seed[:])
	s := append([]byte{}, h[:32]...)
	s[0] &= 248
	s[31] &= 127
	s[31] |= 64
	return priv.Public().(ed25519.PublicKey), priv, littleEndian(s)
}

func mustVerify(t *testing.T, msg, sig []byte, key any) bool {
	t.Helper()
	ok, err := VerifyEd25519(msg, sig, key)
	if err != nil {
		t.Fatalf("VerifyEd25519 returned an error for a well-formed key: %v", err)
	}
	return ok
}

func TestVerifyEd25519_SmallOrderKeyRefused(t *testing.T) {
	smallOrder, _ := sigRuleVectors(t)
	basePoint := append([]byte{0x58}, []byte(strings.Repeat("\x66", 31))...)
	// R = the base point, S = 1: [S]B = R + [k]A holds for a small-order A
	// whenever k is a multiple of 8 — a signature the cofactorless equation
	// (and crypto/ed25519 by itself) accepts. Search a message with such a k.
	sig := append(append([]byte{}, basePoint...), sigRuleLE32(big.NewInt(1))...)
	eight := big.NewInt(8)
	for _, a := range smallOrder {
		var msg []byte
		for n := 0; n < 4096 && msg == nil; n++ {
			m := []byte(fmt.Sprintf("small-order key %d", n))
			if new(big.Int).Mod(sigRuleChallenge(basePoint, a, m), eight).Sign() == 0 {
				msg = m
			}
		}
		if msg == nil {
			t.Fatalf("%x: no message found", a)
		}
		if mustVerify(t, msg, sig, a) {
			t.Errorf("%x: small-order key accepted (raw bytes)", a)
		}
		if mustVerify(t, msg, sig, base64.StdEncoding.EncodeToString(a)) {
			t.Errorf("%x: small-order key accepted (base64)", a)
		}
		// the chain verifier refuses the same key when it loads the key set
		if _, code := PinnedChainKey(a, true); code != KeyPolicySmallOrder {
			t.Errorf("%x: chain key policy says %s", a, code)
		}
	}
}

func TestVerifyEd25519_InvalidPointKeyIsInvalidSignature(t *testing.T) {
	_, invalid := sigRuleVectors(t)
	_, priv, _ := sigRuleKey()
	msg := []byte("witness-only signature rule")
	sig := ed25519.Sign(priv, msg)
	for _, a := range invalid {
		if mustVerify(t, msg, sig, a) {
			t.Errorf("%x: accepted", a)
		}
		if _, code := PinnedChainKey(a, true); code != KeyPolicyInvalidPoint {
			t.Errorf("%x: chain key policy says %s", a, code)
		}
	}
}

func TestVerifyEd25519_MalformedKeyStillAnError(t *testing.T) {
	for _, bad := range []any{make([]byte, 31), make([]byte, 33), "not base64!", 7, nil} {
		if ok, err := VerifyEd25519([]byte("m"), make([]byte, 64), bad); err == nil || ok {
			t.Errorf("%v: ok=%v err=%v, want a normalization error", bad, ok, err)
		}
	}
}

func TestVerifyEd25519_SignatureEncoding(t *testing.T) {
	pub, priv, _ := sigRuleKey()
	msg := []byte("witness-only signature rule")
	honest := ed25519.Sign(priv, msg)
	if !mustVerify(t, msg, honest, []byte(pub)) || !chainStrictVerify(pub, msg, honest) {
		t.Fatal("honest signature refused")
	}
	if !mustVerify(t, msg, honest, base64.StdEncoding.EncodeToString(pub)) {
		t.Fatal("honest signature refused with a base64 key")
	}
	// S >= L: the honest signature with S + L.
	sPlusL := new(big.Int).Add(littleEndian(honest[32:]), edL)
	if sPlusL.BitLen() > 256 {
		t.Fatal("S + L does not fit 32 bytes")
	}
	bad := append(append([]byte{}, honest[:32]...), sigRuleLE32(sPlusL)...)
	if mustVerify(t, msg, bad, []byte(pub)) || chainStrictVerify(pub, msg, bad) {
		t.Error("S + L accepted")
	}
	// Not 64 bytes.
	for _, s := range [][]byte{honest[:63], append(append([]byte{}, honest...), 0), nil} {
		if mustVerify(t, msg, s, []byte(pub)) {
			t.Errorf("%d-byte signature accepted", len(s))
		}
	}
	// Non-canonical R: y = p + 3, a curve point that is not of small order.
	r := append([]byte{0xf0}, []byte(strings.Repeat("\xff", 30)+"\x7f")...)
	bad = append(append([]byte{}, r...), honest[32:]...)
	if mustVerify(t, msg, bad, []byte(pub)) || chainStrictVerify(pub, msg, bad) {
		t.Error("non-canonical R accepted")
	}
}

// Drift: the witness-only path and the chain path refuse all 14 small-order
// encodings as R. S = k·a mod L with R the small-order encoding (the nonce-0
// construction): for R = the identity this is the signature crypto/ed25519
// by itself accepts.
func TestVerifyEd25519_BothPathsRefuseEverySmallOrderR(t *testing.T) {
	smallOrder, _ := sigRuleVectors(t)
	pub, _, scalar := sigRuleKey()
	msg := []byte("witness-only signature rule")
	for _, r := range smallOrder {
		s := new(big.Int).Mod(new(big.Int).Mul(sigRuleChallenge(r, pub, msg), scalar), edL)
		sig := append(append([]byte{}, r...), sigRuleLE32(s)...)
		if mustVerify(t, msg, sig, []byte(pub)) {
			t.Errorf("R %x: witness-only path accepted", r)
		}
		if chainStrictVerify(pub, msg, sig) {
			t.Errorf("R %x: chain path accepted", r)
		}
	}
}

// Drift, helper level: the shared list is exactly the seven values of the 14
// vendored encodings, the shared helper names each of the 14, and the
// primitive refuses each as R whatever S is. Removing any one list entry
// turns this red (the nonce-0 test above only notices the identity entry,
// because the other constructions fail the equation).
func TestVerifyEd25519_SharedListIsExactlyTheSevenValues(t *testing.T) {
	smallOrder, _ := sigRuleVectors(t)
	pub, priv, _ := sigRuleKey()
	msg := []byte("witness-only signature rule")
	honest := ed25519.Sign(priv, msg)
	want := map[string]bool{}
	for _, e := range smallOrder {
		y := append([]byte{}, e...)
		y[31] &= 0x7f
		want[hex.EncodeToString(y)] = true
		if !smallOrderEncoding(e) {
			t.Errorf("%x: the shared helper does not name this small-order encoding", e)
		}
		sig := append(append([]byte{}, e...), honest[32:]...)
		if mustVerify(t, msg, sig, []byte(pub)) {
			t.Errorf("R %x accepted", e)
		}
	}
	if len(want) != 7 || len(chainSmallOrderY) != 7 {
		t.Fatalf("%d vendored values, %d list entries, want 7 and 7", len(want), len(chainSmallOrderY))
	}
	for _, y := range chainSmallOrderY {
		if !want[y] {
			t.Errorf("list entry %s is not one of the vendored small-order values", y)
		}
		delete(want, y)
	}
	for y := range want {
		t.Errorf("vendored small-order value %s is missing from the list", y)
	}
	basePoint := append([]byte{0x58}, []byte(strings.Repeat("\x66", 31))...)
	for _, good := range [][]byte{basePoint, pub, honest[:32]} {
		if smallOrderEncoding(good) {
			t.Errorf("%x named small-order", good)
		}
	}
}

// A genuine signature verifies when message, signature and key are slices
// into larger buffers (non-zero offset, spare capacity), and the inputs are
// left untouched.
func TestVerifyEd25519_SlicesIntoLargerBuffers(t *testing.T) {
	pub, priv, _ := sigRuleKey()
	msg := []byte("witness-only signature rule")
	honest := ed25519.Sign(priv, msg)
	embed := func(b []byte) ([]byte, []byte) {
		big := make([]byte, len(b)+29, len(b)+64)
		for i := range big {
			big[i] = 0xaa
		}
		copy(big[11:], b)
		return big[11 : 11+len(b)], big
	}
	m, mBig := embed(msg)
	s, sBig := embed(honest)
	k, kBig := embed(pub)
	before := [][]byte{append([]byte{}, mBig...), append([]byte{}, sBig...), append([]byte{}, kBig...)}
	if !mustVerify(t, m, s, k) {
		t.Fatal("genuine signature refused when given as slices into larger buffers")
	}
	if !mustVerify(t, m, s, base64.StdEncoding.EncodeToString(k)) {
		t.Fatal("genuine signature refused with a base64 key")
	}
	for i, b := range [][]byte{mBig, sBig, kBig} {
		if string(b) != string(before[i]) {
			t.Errorf("input buffer %d was modified", i)
		}
	}
}

// Drift: signature.go calls the chain rule and holds no list or library
// verify call of its own.
func TestVerifyEd25519_UsesTheChainRule(t *testing.T) {
	b, err := os.ReadFile("signature.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, want := range []string{
		"smallOrderEncoding(raw) || !canonicalCurvePoint(raw)",
		"return chainStrictVerify(ed25519.PublicKey(raw), message, signature), nil",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("signature.go no longer contains %q", want)
		}
	}
	if strings.Contains(src, "ed25519.Verify(") {
		t.Error("signature.go calls crypto/ed25519.Verify itself")
	}
	if regexp.MustCompile(`[0-9a-f]{64}`).MatchString(src) {
		t.Error("signature.go holds a 32-byte hex literal (a second list?)")
	}
}

// Prechecks, pinned without crypto/ed25519. The library also refuses S >= L
// and an off-curve key, so a wrong constant or a disabled point check would
// stay invisible in the tests above.
func TestVerifyEd25519_PrechecksPinnedDirectly(t *testing.T) {
	_, invalid := sigRuleVectors(t)
	pub, priv, _ := sigRuleKey()
	basePoint := append([]byte{0x58}, []byte(strings.Repeat("\x66", 31))...)
	sigWith := func(r []byte, s *big.Int) []byte { return append(append([]byte{}, r...), sigRuleLE32(s)...) }
	one := big.NewInt(1)
	two255 := new(big.Int).Lsh(one, 255)
	// L and p written out here, independent of the constants under test.
	tail, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	wantL := new(big.Int).Add(new(big.Int).Lsh(one, 252), tail)
	wantP := new(big.Int).Sub(two255, big.NewInt(19))
	if edL.Cmp(wantL) != 0 || edP.Cmp(wantP) != 0 {
		t.Fatalf("curve constants: L = %s, p = %s", edL, edP)
	}

	// S < L.
	for _, tc := range []struct {
		name string
		s    *big.Int
		want bool
	}{
		{"0", big.NewInt(0), true},
		{"L-1", new(big.Int).Sub(wantL, one), true},
		{"L", new(big.Int).Set(wantL), false},
		{"L+1", new(big.Int).Add(wantL, one), false},
		{"2^256-1", new(big.Int).Sub(new(big.Int).Lsh(one, 256), one), false},
	} {
		if got := chainSignaturePrecheck(sigWith(basePoint, tc.s)); got != tc.want {
			t.Errorf("precheck with S = %s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if chainSignaturePrecheck(sigWith(basePoint, one)[:63]) {
		t.Error("63-byte signature passed the precheck")
	}
	// R: y = p-1, p, p+1, 2^255-1 fail; an ordinary R passes.
	ys := map[string]*big.Int{
		"p-1": new(big.Int).Sub(wantP, one), "p": new(big.Int).Set(wantP), "p+1": new(big.Int).Add(wantP, one),
		"2^255-1": new(big.Int).Sub(two255, one),
	}
	for name, y := range ys {
		if chainSignaturePrecheck(sigWith(sigRuleLE32(y), one)) {
			t.Errorf("R with y = %s passed the precheck", name)
		}
	}
	if !chainSignaturePrecheck(sigWith(pub, one)) {
		t.Error("an ordinary R failed the precheck")
	}
	// Point check.
	offCurve := sigRuleLE32(big.NewInt(2)) // y = 2 has no x
	if canonicalCurvePoint(offCurve) {
		t.Error("y = 2 named a curve point")
	}
	for _, k := range invalid {
		if canonicalCurvePoint(k) {
			t.Errorf("%x named a canonical curve point", k)
		}
	}
	pMinus1 := sigRuleLE32(ys["p-1"]) // on the curve, x = 0: canonical with the sign bit clear only
	signSet := append([]byte{}, pMinus1...)
	signSet[31] |= 0x80
	if !canonicalCurvePoint(pMinus1) || canonicalCurvePoint(signSet) || !smallOrderEncoding(pMinus1) {
		t.Error("y = p-1: point check or small-order list wrong")
	}
	for _, name := range []string{"p", "p+1", "2^255-1"} {
		if canonicalCurvePoint(sigRuleLE32(ys[name])) {
			t.Errorf("y = %s named a canonical curve point", name)
		}
	}
	if !smallOrderEncoding(sigRuleLE32(ys["p"])) || !smallOrderEncoding(sigRuleLE32(ys["p+1"])) || smallOrderEncoding(sigRuleLE32(ys["2^255-1"])) {
		t.Error("small-order list: y = p, p+1 must be named, 2^255-1 must not")
	}
	if !canonicalCurvePoint(basePoint) || !canonicalCurvePoint(pub) {
		t.Error("an honest point failed the point check")
	}
	// Through the primitive: an off-curve key is an invalid signature.
	msg := []byte("witness-only signature rule")
	if mustVerify(t, msg, ed25519.Sign(priv, msg), offCurve) {
		t.Error("off-curve key accepted")
	}
	// The list has exactly seven entries.
	if len(chainSmallOrderY) != 7 {
		t.Errorf("%d small-order list entries, want exactly 7", len(chainSmallOrderY))
	}
}

// versionValue decides on the value, never by converting an out-of-range
// float64 to int (that conversion differs between arm64 and amd64).
func TestVersionValue(t *testing.T) {
	for _, tc := range []struct {
		in   any
		want int
		ok   bool
	}{
		{float64(0), 0, true}, {float64(2), 2, true}, {float64(3), 3, true},
		{float64(9007199254740992), versionClamp, true},
		{float64(9223372036854775808), versionClamp, true},  // 2^63
		{float64(18446744073709549568), versionClamp, true}, // the largest float64 below 2^64
		{float64(18446744073709551616), 0, false},           // 2^64
		{float64(1e300), 0, false},
		{float64(-1), 0, false}, {float64(2.5), 0, false},
		{json.Number("3"), 3, true}, {json.Number("18446744073709551615"), versionClamp, true},
		{json.Number("18446744073709551616"), 0, false}, {json.Number("3.0"), 0, false}, {json.Number("-1"), 0, false},
		{3, 3, true}, {-1, 0, false},
		{"3", 0, false}, {true, 0, false}, {[]any{float64(3)}, 0, false}, {map[string]any{}, 0, false}, {nil, 0, false},
	} {
		got, ok := versionValue(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("versionValue(%#v) = %d, %v; want %d, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
