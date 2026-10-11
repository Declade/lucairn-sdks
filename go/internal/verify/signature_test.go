package verify

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
)

// The witness-only primitive (VerifyEd25519) applies its own Ed25519
// acceptance rule before the bytes reach crypto/ed25519: a small-order R, a
// small-order or non-canonical public key and S >= L are refused, whatever
// the library accepts by itself (T-1322). Every assertion here is a refusal,
// or an honest signature verifying.

// The shared vector file: the SAME bytes sit in
//
//	ts/src/verify-certificate/__fixtures__/ed25519-rule-vectors.json
//	python/tests/fixtures/ed25519-rule-vectors.json
//	go/internal/verify/testdata/ed25519-rule-vectors.json
//
// and each SDK's test pins this sha256, so the three copies of the rule are
// held to one set of inputs and expected results.
const sigRuleVectorsSHA256 = "26033d6336fd735dc5c4db068fbcb682cbd6385f8167b8afbb5d44769062fd20"

type sigRuleVector struct {
	ID        string `json:"id"`
	Group     string `json:"group"`
	PublicKey string `json:"public_key_hex"`
	Message   string `json:"message_hex"`
	Signature string `json:"signature_hex"`
	Expected  string `json:"expected"`
}

func sigRuleHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in vector file: %v", err)
	}
	return b
}

func sigRuleVectors(t *testing.T) []sigRuleVector {
	t.Helper()
	data := loadV3Fixture(t, "ed25519-rule-vectors.json")
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != sigRuleVectorsSHA256 {
		t.Fatalf("ed25519-rule-vectors.json sha256 = %s, want %s (the file must be identical in the three SDKs)", got, sigRuleVectorsSHA256)
	}
	var doc struct {
		Vectors []sigRuleVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Vectors
}

func sigRuleSmallOrder(t *testing.T) [][]byte {
	t.Helper()
	var out [][]byte
	seen := map[string]bool{}
	for _, v := range sigRuleVectors(t) {
		if v.Group == "small_order_key" {
			out = append(out, sigRuleHex(t, v.PublicKey))
			seen[v.PublicKey] = true
		}
	}
	if len(out) != 14 || len(seen) != 14 {
		t.Fatalf("%d small-order encodings (%d distinct), want 14", len(out), len(seen))
	}
	return out
}

func mustVerify(t *testing.T, msg, sig []byte, key any) bool {
	t.Helper()
	ok, err := VerifyEd25519(msg, sig, key)
	if err != nil {
		t.Fatalf("VerifyEd25519 returned an error for a well-formed key: %v", err)
	}
	return ok
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

func TestVerifyEd25519_SharedVectorCoverage(t *testing.T) {
	vectors := sigRuleVectors(t)
	count := map[string]int{}
	accept := 0
	smallR := map[string]bool{}
	for _, v := range vectors {
		count[v.Group]++
		if v.Expected == "accept" {
			accept++
		}
		if v.Group == "small_order_r" {
			smallR[v.Signature[:64]] = true
		}
	}
	sigRuleSmallOrder(t)
	if len(smallR) != 14 || count["invalid_point_key"] < 3 || count["noncanonical_s"] < 1 || count["noncanonical_r"] < 1 || accept < 5 || len(vectors) != 48 {
		t.Fatalf("vector file coverage: %d vectors, %v, %d small-order R, %d accept", len(vectors), count, len(smallR), accept)
	}
}

func TestVerifyEd25519_SharedVectors(t *testing.T) {
	for _, v := range sigRuleVectors(t) {
		v := v
		t.Run(v.ID, func(t *testing.T) {
			if v.Expected != "accept" && v.Expected != "refuse" {
				t.Fatalf("expected = %q", v.Expected)
			}
			want := v.Expected == "accept"
			key, msg, sig := sigRuleHex(t, v.PublicKey), sigRuleHex(t, v.Message), sigRuleHex(t, v.Signature)
			if got := mustVerify(t, msg, sig, key); got != want {
				t.Errorf("raw key: got %v, want %v", got, want)
			}
			// the base64 form of the key takes the same path
			if got := mustVerify(t, msg, sig, base64.StdEncoding.EncodeToString(key)); got != want {
				t.Errorf("base64 key: got %v, want %v", got, want)
			}
		})
	}
}

func TestVerifyEd25519_RuleConstants(t *testing.T) {
	// L = 2^252 + 27742317777372353535851937790883648493
	c, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	if want := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 252), c); edL.Cmp(want) != 0 {
		t.Fatalf("edL = %s", edL)
	}
	// d = -121665/121666 mod p  <=>  d * 121666 + 121665 = 0 mod p
	chk := new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(edD, big.NewInt(121666)), big.NewInt(121665)), edP)
	if chk.Sign() != 0 {
		t.Fatal("edD is not -121665/121666 mod p")
	}
}

// Fresh keys made in the test: no false refusal, with the key's sign bit
// clear and set.
func TestVerifyEd25519_FreshKeysVerify(t *testing.T) {
	msg := []byte("witness-only signature rule")
	clear, set := 0, 0
	for i := 0; i < 400 && (clear < 4 || set < 4); i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		sig := ed25519.Sign(priv, msg)
		if !mustVerify(t, msg, sig, []byte(pub)) {
			t.Fatalf("genuine signature refused for key %x", pub)
		}
		if !mustVerify(t, msg, sig, base64.StdEncoding.EncodeToString(pub)) {
			t.Fatalf("genuine signature refused for base64 key %x", pub)
		}
		if pub[31]&0x80 != 0 {
			set++
		} else {
			clear++
		}
	}
	if clear < 4 || set < 4 {
		t.Fatalf("sign bit clear %d / set %d", clear, set)
	}
}

func TestVerifyEd25519_FreshKeyRefusals(t *testing.T) {
	msg := []byte("witness-only signature rule")
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, msg)
	if !mustVerify(t, msg, sig, []byte(pub)) {
		t.Fatal("genuine signature refused")
	}
	// S + L
	sPlusL := new(big.Int).Add(littleEndian(sig[32:]), edL)
	if sPlusL.BitLen() > 256 {
		t.Fatal("S + L does not fit 32 bytes")
	}
	if mustVerify(t, msg, append(append([]byte{}, sig[:32]...), sigRuleLE32(sPlusL)...), []byte(pub)) {
		t.Error("S + L accepted")
	}
	// every small-order encoding as R and as key
	for _, e := range sigRuleSmallOrder(t) {
		if mustVerify(t, msg, append(append([]byte{}, e...), sig[32:]...), []byte(pub)) {
			t.Errorf("R %x accepted", e)
		}
		if mustVerify(t, msg, sig, e) {
			t.Errorf("key %x accepted", e)
		}
	}
	// not 64 bytes
	for _, s := range [][]byte{sig[:63], append(append([]byte{}, sig...), 0), nil} {
		if mustVerify(t, msg, s, []byte(pub)) {
			t.Errorf("%d-byte signature accepted", len(s))
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

// Every small-order encoding, one by one, at helper level: on the list,
// refused as key, refused as R (S = 1 is below L, so only R decides).
func TestEd25519Rule_EverySmallOrderEncoding(t *testing.T) {
	sOne := sigRuleLE32(big.NewInt(1))
	masked := map[string]bool{}
	for _, e := range sigRuleSmallOrder(t) {
		before := append([]byte{}, e...)
		if !smallOrderEncoding(e) {
			t.Errorf("%x: not on the small-order list", e)
		}
		if ed25519KeyAcceptable(e) {
			t.Errorf("%x: accepted as key", e)
		}
		if ed25519SignatureEncodingAcceptable(append(append([]byte{}, e...), sOne...)) {
			t.Errorf("%x: accepted as R", e)
		}
		if string(before) != string(e) {
			t.Errorf("%x: the helper wrote to the caller's slice", before)
		}
		m := append([]byte{}, e...)
		m[31] &= 0x7f
		masked[string(m)] = true
	}
	if len(masked) != 7 {
		t.Fatalf("%d distinct values with the sign bit cleared, want 7", len(masked))
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if smallOrderEncoding(pub) || !ed25519KeyAcceptable(pub) || !ed25519SignatureEncodingAcceptable(append(append([]byte{}, pub...), sOne...)) {
		t.Fatalf("an ordinary point %x is refused", pub)
	}
}

// Slices that are views into a larger array verify like fresh slices, and
// the caller's bytes are never written to.
func TestVerifyEd25519_SliceViewsAndNoMutation(t *testing.T) {
	msg := []byte("witness-only signature rule")
	var pub ed25519.PublicKey
	var priv ed25519.PrivateKey
	for pub == nil || pub[31]&0x80 == 0 { // a key whose sign bit is set
		var err error
		if pub, priv, err = ed25519.GenerateKey(rand.Reader); err != nil {
			t.Fatal(err)
		}
	}
	sig := ed25519.Sign(priv, msg)
	backing := make([]byte, 200)
	for i := range backing {
		backing[i] = 0xff
	}
	copy(backing[17:], sig)
	copy(backing[100:], pub)
	copy(backing[140:], msg)
	before := append([]byte{}, backing...)
	if !mustVerify(t, backing[140:140+len(msg)], backing[17:81], backing[100:132]) {
		t.Fatal("genuine signature refused on slice views")
	}
	if !mustVerify(t, msg, sig, []byte(pub)) {
		t.Fatal("genuine signature refused")
	}
	if string(before) != string(backing) {
		t.Fatal("VerifyEd25519 wrote to the caller's bytes")
	}
}

// --- signature text rules (shared with the TypeScript and Python SDKs) ---

func TestTextRule_WhiteSpaceSet(t *testing.T) {
	blank := []rune{0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000}
	if !isBlankSignatureText("") || !isBlankSignatureText(string(blank)) {
		t.Fatal("white space not blank")
	}
	for _, r := range blank {
		if !isBlankSignatureText(string(r)) {
			t.Errorf("U+%04X is not blank", r)
		}
	}
	for _, r := range []rune{0x1c, 0x1d, 0x1e, 0x1f, 0xfeff, 0x200b, 0x180e, 0x00, 0x41} {
		if isBlankSignatureText(string(r)) || isBlankSignatureText(" "+string(r)+" ") {
			t.Errorf("U+%04X counts as blank", r)
		}
	}
}

func TestTextRule_CanonicalBase64(t *testing.T) {
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = 7
	}
	text := base64.StdEncoding.EncodeToString(raw)
	if got, err := decodeSignatureText(text); err != nil || string(got) != string(raw) {
		t.Fatalf("canonical text refused: %v", err)
	}
	nonzero := text[:len(text)-3] + "x==" // "Bw==" with non-zero padding bits
	if got, err := base64.StdEncoding.DecodeString(nonzero); err != nil || string(got) != string(raw) {
		t.Fatalf("test vector: %v", err)
	}
	for _, bad := range []string{text[:len(text)-2], text + "!", " " + text, text + "\n", text[:40] + "\r\n" + text[40:], nonzero} {
		if _, err := decodeSignatureText(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestIntegerTokenProblem(t *testing.T) {
	ok := []string{
		`{"protocol_version":2}`, `{"protocol_version": 2 ,"signable_protocol_version_emitted":3}`,
		`{"protocol_version":0}`, `{"protocol_version":18446744073709551615}`, `{"protocol_version":99999999999999999999}`,
		`{}`, `{"protocol_version":null}`, `{"protocol_version":"2"}`, `{"protocol_version":true}`, `{"protocol_version":[2.5]}`,
		`{"signable_protocol_version_emitted":null}`, `{"other":2.5,"claims":[{"protocol_version":2.5}]}`,
		`[1.5]`, `not json`, ``,
	}
	for _, s := range ok {
		if p := IntegerTokenProblem([]byte(s)); p != "" {
			t.Errorf("%s: %s", s, p)
		}
	}
	bad := []string{
		`{"protocol_version":2.0}`, `{"protocol_version":2.0000000000000001}`, `{"protocol_version":2e0}`, `{"protocol_version":2E0}`,
		`{"protocol_version":-2}`, `{"protocol_version":-0}`, `{"protocol_version":2.5}`, `{"protocol_version":100000000000000000000}`,
		`{"protocol_version":2,"signable_protocol_version_emitted":3.0}`, `{"signable_protocol_version_emitted":3e0}`,
		`{"signable_protocol_version_emitted":-3}`, `{"protocol_version":2,"protocol_version":2.0}`,
	}
	for _, s := range bad {
		if p := IntegerTokenProblem([]byte(s)); p == "" {
			t.Errorf("%s: no problem reported", s)
		}
	}
	// last duplicate wins, as in encoding/json
	if p := IntegerTokenProblem([]byte(`{"protocol_version":2.0,"protocol_version":2}`)); p != "" {
		t.Errorf("last duplicate is an integer token: %s", p)
	}
}
