package verify

// Text rules of the witness-only verifier, written out so the TypeScript,
// Python and Go SDKs judge the same signature TEXT and the same number
// TOKENS the same way.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// isBlankSignatureText: the field is empty or holds only white space. The
// set is unicode.IsSpace (what strings.TrimSpace trims): U+0009–000D, U+0020,
// U+0085, U+00A0, U+1680, U+2000–200A, U+2028, U+2029, U+202F, U+205F,
// U+3000. The TypeScript and Python SDKs test against the same set.
func isBlankSignatureText(text string) bool {
	return strings.TrimSpace(text) == ""
}

// decodeSignatureText decodes a signature field. The text must be CANONICAL
// standard padded base64 (alphabet A-Z a-z 0-9 + /, '=' padding, nothing
// else): decode, re-encode, compare. base64.StdEncoding by itself skips CR
// and LF and accepts non-zero padding bits.
func decodeSignatureText(text string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(raw) != text {
		return nil, errors.New("not canonical standard padded base64")
	}
	return raw, nil
}

// integerTokenFields are the integers the witness-only check reads from the
// top level of a certificate.
var integerTokenFields = []string{"protocol_version", "signable_protocol_version_emitted"}

// IntegerTokens inspects the RAW JSON text of a certificate. For each of the
// integers the witness-only check reads from the top level it looks at the
// number TOKEN:
//
//   - problem is non-empty when a token is a number that is not a plain
//     integer: digits only (no sign, fraction or exponent), at most 20 digits
//     and a value of at most 2^64 − 1;
//   - tokens holds the exact digits of each field that IS a plain integer
//     token, so the caller can hand the exact value on instead of the float64
//     encoding/json produced from it (a float64 cannot hold every integer
//     above 2^53).
//
// A caller that hands the SDK an already decoded map has lost the token, so
// this applies to raw-bytes input only. A field that is absent, or whose
// value is not a number (null, a string, ...), is left to the structural
// checks of Parse. Text that is not a JSON object returns ("", nil): the
// existing decode reports it.
//
// Only these two top-level fields are looked at. Neither is part of the
// signable reconstruction, which keeps working on the values the caller's
// own json.Unmarshal produced.
func IntegerTokens(raw []byte) (problem string, tokens map[string]json.Number) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return "", nil
	}
	tokens = map[string]json.Number{}
	for _, field := range integerTokenFields {
		tok := bytes.TrimSpace(top[field])
		if len(tok) == 0 || (tok[0] != '-' && (tok[0] < '0' || tok[0] > '9')) {
			continue
		}
		if _, ok := versionValue(json.Number(tok)); !ok {
			return field + " must be an integer token: digits only (no sign, fraction or exponent), at most 20 digits, at most 2^64 - 1", nil
		}
		tokens[field] = json.Number(tok)
	}
	return "", tokens
}
