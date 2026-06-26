// Package verify contains the Veil Certificate verification pipeline.
//
// It is byte-equivalent to the TS and Python ports:
//   - <sdks-repo>/ts/src/verify-certificate/canonical-json.ts
//   - <sdks-repo>/python/src/lucairn/verify_certificate/canonical_json.py
//
// All three descend from dual-sandbox-architecture/pkg/veil/canonical.go,
// the server-side canonical used by the Veil Witness assembler.
package verify

import (
	"fmt"
	"sort"
	"strconv"
	"unicode/utf16"
	"unicode/utf8"
)

// CanonicalJSON emits byte-canonical JSON for the Veil signing subset.
//
// This is byte-identical to the witness signer
// (dual-sandbox-architecture/pkg/veil/canonical.go) and the TS / Python ports:
//   - maps with keys sorted bytewise over their UTF-8 bytes, at every nesting level;
//   - strings serialized like Python json.dumps(ensure_ascii=True): EVERY rune
//     >= U+0080 escaped to a lowercase \uXXXX (supplementary plane -> UTF-16
//     surrogate pair), control chars to their short escapes or \u00XX, and
//     <, >, & emitted LITERALLY (the witness does NOT HTML-escape them);
//   - integers as unquoted numbers; zero whitespace; no trailing newline.
//
// Earlier revisions delegated to json.Marshal, which (a) HTML-escapes <, >, &
// and (b) emits runes >= U+0080 as raw UTF-8 — both diverge from the witness,
// silently breaking signature verification on any non-ASCII signable. This
// explicit encoder closes that divergence; the golden-hex fixture test
// (incl. the non-ASCII vector) proves byte-equality against the witness.
func CanonicalJSON(value any) ([]byte, error) {
	if err := validateCanonical(value, map[uintptr]struct{}{}); err != nil {
		return nil, err
	}
	var buf []byte
	buf, err := appendCanonical(buf, value)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// appendCanonical appends the canonical encoding of v to dst and returns the
// extended slice. It assumes validateCanonical has already rejected disallowed
// types, so the type switch here is exhaustive over the permitted set.
func appendCanonical(dst []byte, v any) ([]byte, error) {
	switch x := v.(type) {
	case nil:
		return append(dst, "null"...), nil
	case bool:
		if x {
			return append(dst, "true"...), nil
		}
		return append(dst, "false"...), nil
	case string:
		return appendPythonAsciiString(dst, x), nil
	case int:
		return strconv.AppendInt(dst, int64(x), 10), nil
	case int8:
		return strconv.AppendInt(dst, int64(x), 10), nil
	case int16:
		return strconv.AppendInt(dst, int64(x), 10), nil
	case int32:
		return strconv.AppendInt(dst, int64(x), 10), nil
	case int64:
		return strconv.AppendInt(dst, x, 10), nil
	case uint:
		return strconv.AppendUint(dst, uint64(x), 10), nil
	case uint8:
		return strconv.AppendUint(dst, uint64(x), 10), nil
	case uint16:
		return strconv.AppendUint(dst, uint64(x), 10), nil
	case uint32:
		return strconv.AppendUint(dst, uint64(x), 10), nil
	case uint64:
		return strconv.AppendUint(dst, x, 10), nil
	case []any:
		dst = append(dst, '[')
		for i, item := range x {
			if i > 0 {
				dst = append(dst, ',')
			}
			var err error
			if dst, err = appendCanonical(dst, item); err != nil {
				return nil, err
			}
		}
		return append(dst, ']'), nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// Bytewise sort over the keys' UTF-8 bytes. Go strings are UTF-8, so the
		// default string comparison IS a bytewise comparison — matching Go's
		// encoding/json map-key order, Python's sorted(key=k.encode("utf-8")),
		// and the TS compareUtf8Bytes comparator.
		sort.Strings(keys)
		dst = append(dst, '{')
		for i, k := range keys {
			if i > 0 {
				dst = append(dst, ',')
			}
			dst = appendPythonAsciiString(dst, k)
			dst = append(dst, ':')
			var err error
			if dst, err = appendCanonical(dst, x[k]); err != nil {
				return nil, err
			}
		}
		return append(dst, '}'), nil
	default:
		// validateCanonical should have rejected anything else already.
		return nil, fmt.Errorf("canonical_json: unsupported type %T", v)
	}
}

// appendPythonAsciiString appends a JSON string literal whose bytes match
// Python's json.dumps(s, ensure_ascii=True) and the witness signer
// (pkg/veil/canonical.go:encodePythonAsciiString). Char-class table:
//
//	U+0008 -> \b   U+0009 -> \t   U+000A -> \n   U+000C -> \f   U+000D -> \r
//	other U+0000..U+001F -> \u00XX (lowercase)
//	U+0022 (") -> \"      U+005C (\) -> \\
//	U+0020..U+007E (incl < > &) -> literal (except the two above)
//	U+007F (DEL) -> 
//	U+0080..U+FFFF -> \uXXXX (lowercase)
//	U+10000..U+10FFFF -> \uHHHH\uLLLL (UTF-16 surrogate pair)
func appendPythonAsciiString(dst []byte, s string) []byte {
	const hex = "0123456789abcdef"
	dst = append(dst, '"')
	i := 0
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == '"':
			dst = append(dst, '\\', '"')
		case r == '\\':
			dst = append(dst, '\\', '\\')
		case r == '\b':
			dst = append(dst, '\\', 'b')
		case r == '\t':
			dst = append(dst, '\\', 't')
		case r == '\n':
			dst = append(dst, '\\', 'n')
		case r == '\f':
			dst = append(dst, '\\', 'f')
		case r == '\r':
			dst = append(dst, '\\', 'r')
		case r < 0x20:
			dst = append(dst, '\\', 'u', '0', '0', hex[r>>4], hex[r&0xF])
		case r < 0x7F:
			dst = append(dst, byte(r))
		case r == 0x7F:
			dst = append(dst, '\\', 'u', '0', '0', '7', 'f')
		case r <= 0xFFFF:
			dst = append(dst, '\\', 'u',
				hex[(r>>12)&0xF], hex[(r>>8)&0xF],
				hex[(r>>4)&0xF], hex[r&0xF])
		default:
			// Supplementary plane -> UTF-16 surrogate pair, both halves lowercase.
			hi, lo := utf16.EncodeRune(r)
			if hi == 0xFFFD && lo == 0xFFFD {
				// utf8.DecodeRuneInString already substitutes invalid bytes with
				// utf8.RuneError (U+FFFD), so this path is unreachable for valid
				// inputs; emit a single replacement char to stay valid JSON.
				dst = append(dst, '\\', 'u', 'f', 'f', 'f', 'd')
				continue
			}
			dst = append(dst, '\\', 'u',
				hex[(hi>>12)&0xF], hex[(hi>>8)&0xF],
				hex[(hi>>4)&0xF], hex[hi&0xF],
				'\\', 'u',
				hex[(lo>>12)&0xF], hex[(lo>>8)&0xF],
				hex[(lo>>4)&0xF], hex[lo&0xF])
		}
	}
	return append(dst, '"')
}

func validateCanonical(v any, seen map[uintptr]struct{}) error {
	switch x := v.(type) {
	case nil, bool, string,
		int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64:
		return nil
	case float32, float64:
		return fmt.Errorf("canonical_json: float %v not permitted — use int for integer leaves", x)
	case []byte:
		return fmt.Errorf("canonical_json: []byte not permitted — encode as base64 string before passing")
	case []any:
		for i, item := range x {
			if err := validateCanonical(item, seen); err != nil {
				return fmt.Errorf("canonical_json: [%d]: %w", i, err)
			}
		}
		return nil
	case map[string]any:
		for k, val := range x {
			if err := validateCanonical(val, seen); err != nil {
				return fmt.Errorf("canonical_json: [%q]: %w", k, err)
			}
		}
		return nil
	default:
		// Defensive reject — we only permit the types that appear in the
		// Veil signable subset. Structs / other maps would risk encoding-order
		// divergence from the witness reference.
		return fmt.Errorf("canonical_json: unsupported type %T", v)
	}
}
