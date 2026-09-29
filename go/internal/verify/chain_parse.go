package verify

// The ONE strict document parser of the certificate chain recipe (parity
// corpus spec § Input document), used for the certificate (step 1), the
// signed claim bytes (step 7e) and the v3 sanitizer-hash lookup (step 5c).
// The TS and Python SDKs implement the same grammar; the corpus and the
// vectors in parity_corpus_test.go hold all three to it.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxChainDepth bounds nesting: every array and object counts one level, the
// top-level value is level 1, brackets inside strings do not count.
const MaxChainDepth = 256

// MaxChainInputBytes bounds the certificate input (checked before any
// parsing). It covers an export-shape certificate carrying the inference
// sandbox's full per-turn store of upstream request bodies (16 MiB raw,
// base64 in the export) plus the rest of the certificate, with margin.
const MaxChainInputBytes = 32 << 20

// MaxChainValuesPointerBytes bounds `verified`: the UTF-8 bytes of every
// JSON Pointer in every claim's `values`, all claims together.
const MaxChainValuesPointerBytes = 64 << 20

// scanDepthAndSurrogates walks the raw text once: nesting depth (brackets
// inside strings do not count) and escaped UTF-16 surrogates that are not a
// high escape immediately followed by a low escape. Go's decoder would
// replace an unpaired one with U+FFFD; the recipe refuses it instead.
func scanDepthAndSurrogates(b []byte) error {
	depth := 0
	hex4 := func(i int) (int, bool) {
		if i+4 > len(b) {
			return 0, false
		}
		n, err := strconv.ParseUint(string(b[i:i+4]), 16, 32)
		return int(n), err == nil
	}
	for i := 0; i < len(b); i++ {
		switch b[i] {
		case '"':
			for i++; i < len(b) && b[i] != '"'; i++ {
				if b[i] != '\\' {
					continue
				}
				if i+1 < len(b) && b[i+1] == 'u' {
					r, ok := hex4(i + 2)
					if !ok {
						i++
						continue
					}
					switch {
					case r >= 0xD800 && r <= 0xDBFF:
						if i+7 < len(b) && b[i+6] == '\\' && b[i+7] == 'u' {
							if r2, ok2 := hex4(i + 8); ok2 && r2 >= 0xDC00 && r2 <= 0xDFFF {
								i += 11
								continue
							}
						}
						return errors.New("unpaired surrogate escape")
					case r >= 0xDC00 && r <= 0xDFFF:
						return errors.New("unpaired surrogate escape")
					}
					i += 5
					continue
				}
				i++ // the escaped character
			}
		case '[', '{':
			depth++
			if depth > MaxChainDepth {
				return fmt.Errorf("nesting deeper than %d", MaxChainDepth)
			}
		case ']', '}':
			depth--
		}
	}
	return nil
}

// readValue builds one value from the token stream: objects as
// map[string]any (a key that repeats, compared after escape decoding and
// code point for code point, is an error), arrays as []any, numbers as
// json.Number (lexeme kept).
func readValue(dec *json.Decoder) (any, error) {
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, isDelim := t.(json.Delim)
	if !isDelim {
		return t, nil
	}
	switch d {
	case '{':
		m := map[string]any{}
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			k, ok := kt.(string)
			if !ok {
				return nil, errors.New("object key is not a string")
			}
			if _, dup := m[k]; dup {
				return nil, errors.New("duplicate object key")
			}
			v, err := readValue(dec)
			if err != nil {
				return nil, err
			}
			m[k] = v
		}
		if end, err := dec.Token(); err != nil || end != json.Delim('}') {
			return nil, errors.New("object not closed")
		}
		return m, nil
	case '[':
		arr := []any{}
		for dec.More() {
			v, err := readValue(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		if end, err := dec.Token(); err != nil || end != json.Delim(']') {
			return nil, errors.New("array not closed")
		}
		return arr, nil
	}
	return nil, errors.New("unexpected delimiter")
}

// DecodeDocument parses one strict document: valid UTF-8 with no byte-order
// mark (Go's decoder would otherwise substitute U+FFFD for invalid bytes), at
// most MaxChainDepth levels, no unpaired surrogate escape, no duplicate key
// (after escape decoding), exactly one JSON value with number lexemes kept
// (json.Number), then only JSON whitespace up to EOF. Decoder.More is NOT
// enough for the last rule: it reports false before a stray ']' or '}', so
// the next token must be EOF. No NaN / Infinity (encoding/json refuses them).
//
// The certificate additionally passes the size bound and the case-variant
// key rule (DecodeCertificate); the signed claim bytes pass the case-variant
// key rule at step 7e.
func DecodeDocument(b []byte) (any, error) {
	if !utf8.Valid(b) {
		return nil, errors.New("not UTF-8")
	}
	if err := scanDepthAndSurrogates(b); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := readValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the document")
	}
	return v, nil
}

// DecodeCertificate is step 1's document rule: the MaxChainInputBytes bound
// (checked first), the DecodeDocument grammar, and the case-variant key rule.
func DecodeCertificate(b []byte) (any, error) {
	if len(b) > MaxChainInputBytes {
		return nil, fmt.Errorf("certificate larger than %d bytes", MaxChainInputBytes)
	}
	v, err := DecodeDocument(b)
	if err != nil {
		return nil, err
	}
	if CaseVariantKey(v) {
		return nil, errors.New("an object key folds to a spec key it is not")
	}
	return v, nil
}

// chainSpecKeyList — the keys the recipe reads, in the certificate document
// or in the signed bytes.
var chainSpecKeyList = []string{
	// certificate
	"certificate_id", "request_id", "witness_key_id", "issued_at", "protocol_version", "claims",
	"verification", "signable_protocol_version_emitted", "witness_signature", "signable_v3_signature",
	"client_id", "api_key_id",
	// verification
	"overall_verdict", "cert_tier", "byok_exempt",
	// claims[]
	"claim_id", "service_id", "claim_type", "canonical_payload", "signature", "data_seen", "data_not_seen",
	"bridge", "sanitizer", "inference", "audit",
	// typed objects
	"isolation_probe", "model_used", "response_hash", "upstream_request_bodies",
	"pii_entities_found", "layers_active", "qi_score",
	"k_anonymity", "l_diversity", "risk_score", "threshold", "verdict", "fields_generalized",
	"token_hash", "encryption_enabled", "chain_head_hash", "chain_length",
	// signed bytes
	"payload", "timestamp", "upstream_body_sha256", "inference_outcome",
	"redaction_manifest_hash", "sanitized_fields_hash", "tms_manifest_hash",
}

// chainSpecKeys holds the spec keys; chainSpecFolded each spec key and its
// protojson JSON name, folded.
var chainSpecKeys, chainSpecFolded = func() (map[string]bool, map[string]bool) {
	keys, folded := map[string]bool{}, map[string]bool{}
	for _, k := range chainSpecKeyList {
		keys[k] = true
		folded[FoldKey(k)] = true
		folded[FoldKey(ProtoJSONName(k))] = true
	}
	return keys, folded
}()

// SpecKeys returns the recipe's spec keys, sorted (for tests).
func SpecKeys() []string {
	out := append([]string{}, chainSpecKeyList...)
	sort.Strings(out)
	return out
}

// ProtoJSONName is the protojson JSON name protoc derives from a field name:
// every "_" dropped and the lower-case ASCII letter after it upper-cased
// (byok_exempt → byokExempt). protojson readers accept it next to the proto
// name, so it is refused too.
func ProtoJSONName(s string) string {
	var b []byte
	under := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '_' {
			if under && c >= 'a' && c <= 'z' {
				c -= 'a' - 'A'
			}
			b = append(b, c)
		}
		under = c == '_'
	}
	return string(b)
}

// FoldKey folds ASCII A–Z to lower case, plus the only two non-ASCII letters
// whose Unicode simple case folding reaches an ASCII letter: U+212A KELVIN
// SIGN → k and U+017F LATIN SMALL LETTER LONG S → s. encoding/json matches
// struct fields with that folding, which is why a relabelled key could
// otherwise be read by a typed Go struct.
func FoldKey(k string) string {
	var sb strings.Builder
	for _, r := range k {
		switch {
		case r >= 'A' && r <= 'Z':
			sb.WriteRune(r + ('a' - 'A'))
		case r == 'K':
			sb.WriteByte('k')
		case r == 'ſ':
			sb.WriteByte('s')
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// CaseVariantKey reports whether any object key in v, at any depth, is not a
// spec key but folds to a spec key or to a spec key's protojson JSON name
// (BYOK_EXEMPT, byokExempt, byoK_exempt, …) — refused even when the
// real key is absent.
func CaseVariantKey(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if !chainSpecKeys[k] && chainSpecFolded[FoldKey(k)] {
				return true
			}
			if CaseVariantKey(e) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if CaseVariantKey(e) {
				return true
			}
		}
	}
	return false
}

// ChainSpace is the ONE whitespace set of the recipe (Go's unicode.IsSpace):
// U+0009–U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000–U+200A, U+2028,
// U+2029, U+202F, U+205F, U+3000. Not U+001C–U+001F, not U+200B.
const ChainSpace = " \t\n\v\f\r\u0085                 　"

// ChainTrimSpace trims the ONE whitespace set (step 4 "non-blank", the 7i
// qi_score verdict).
func ChainTrimSpace(s string) string { return strings.Trim(s, ChainSpace) }
