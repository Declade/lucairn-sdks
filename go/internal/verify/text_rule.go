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

// IntegerTokenProblem inspects the RAW JSON text of a certificate and returns
// a non-empty reason when one of the integers the witness-only check reads is
// a number token that is not a plain integer: digits only (no sign, fraction
// or exponent) and at most 20 digits. A caller that hands the SDK an already
// decoded map has lost the token, so this rule applies to raw-bytes input
// only. A field that is absent, or whose value is not a number (null, a
// string, ...), is left to the existing structural checks. Text that is not
// a JSON object returns "" as well: the existing decode reports it.
//
// The decoded values the pipeline works on are NOT produced here — the caller
// keeps its own json.Unmarshal — so this check cannot change what feeds the
// signable reconstruction.
func IntegerTokenProblem(raw []byte) string {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return ""
	}
	for _, field := range integerTokenFields {
		tok := bytes.TrimSpace(top[field])
		if len(tok) == 0 || (tok[0] != '-' && (tok[0] < '0' || tok[0] > '9')) {
			continue
		}
		if len(tok) > 20 {
			return field + " must be an integer of at most 20 digits"
		}
		for _, c := range tok {
			if c < '0' || c > '9' {
				return field + " must be an integer (digits only: no sign, fraction or exponent)"
			}
		}
	}
	return ""
}
