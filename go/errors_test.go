package lucairn

import (
	"errors"
	"strings"
	"testing"
)

func TestConfigError_Error(t *testing.T) {
	err := &ConfigError{Message: "bad"}
	if !strings.HasPrefix(err.Error(), "lucairn: ") {
		t.Errorf("Error() must prefix with 'lucairn: ', got %q", err.Error())
	}
}

func TestHTTPError_StatusAndBody(t *testing.T) {
	err := &HTTPError{Status: 401, Body: map[string]any{"code": "nope"}, Message: "unauthorized"}
	if err.Status != 401 {
		t.Errorf("status = %d, want 401", err.Status)
	}
	if _, ok := err.Body.(map[string]any); !ok {
		t.Errorf("body should be map[string]any, got %T", err.Body)
	}
}

func TestHTTPError_Unwrap(t *testing.T) {
	inner := errors.New("inner")
	err := &HTTPError{Status: 500, Err: inner}
	if !errors.Is(err, inner) {
		t.Errorf("errors.Is should unwrap to inner")
	}
}

func TestCertificateError_Error_WithID(t *testing.T) {
	err := &CertificateError{
		Reason:        ReasonInvalidSignature,
		CertificateID: "veil_xyz",
		Message:       "bad",
	}
	msg := err.Error()
	if !strings.Contains(msg, "invalid_signature") {
		t.Errorf("message should include reason: %q", msg)
	}
	if !strings.Contains(msg, "veil_xyz") {
		t.Errorf("message should include certificate_id: %q", msg)
	}
}

func TestCertificateError_Error_WithoutID(t *testing.T) {
	err := &CertificateError{
		Reason:  ReasonMalformed,
		Message: "bad",
	}
	msg := err.Error()
	if !strings.Contains(msg, "malformed") {
		t.Errorf("message should include reason: %q", msg)
	}
	if strings.Contains(msg, "certificate_id=") {
		t.Errorf("message should not include empty certificate_id: %q", msg)
	}
}

func TestTimeoutError_Unwrap(t *testing.T) {
	inner := errors.New("deadline")
	err := &TimeoutError{Message: "slow", Err: inner}
	if !errors.Is(err, inner) {
		t.Errorf("errors.Is should unwrap to inner")
	}
}

func TestAllErrorsSatisfyErrorInterface(t *testing.T) {
	var _ Error = &ConfigError{}
	var _ Error = &HTTPError{}
	var _ Error = &TimeoutError{}
	var _ Error = &NetworkError{}
	var _ Error = &CertificateError{}
	var _ Error = &ResponseValidationError{}
}

func TestResponseValidationError_BodyAndUnwrap(t *testing.T) {
	inner := errors.New("json decode failed")
	err := &ResponseValidationError{
		Body:    []byte(`{"not": "a cert"}`),
		Message: "response body failed to deserialize",
		Err:     inner,
	}
	if string(err.Body) != `{"not": "a cert"}` {
		t.Errorf("body preservation failed")
	}
	if !errors.Is(err, inner) {
		t.Errorf("errors.Is should unwrap to inner")
	}
}

func TestResponseValidationError_IsNotHTTPError(t *testing.T) {
	// Core invariant: a response-validation failure is NOT an HTTP error.
	// Callers filtering on *HTTPError must NOT accidentally catch it.
	err := error(&ResponseValidationError{Message: "bad shape"})
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		t.Errorf("must not satisfy *HTTPError")
	}
}

// rawBodyBytes simplification regression tests — ToB-recommended. Lock
// the always-json.Marshal behaviour so a future refactor can't regress
// to type-switch special-casing.

// A literal `null` JSON 2xx response parses to Go nil; rawBodyBytes must
// emit []byte("null") (the valid JSON null literal) so the caller can
// distinguish "gateway sent null" from "SDK forgot to populate .Body".
// The earlier short-circuit (if body == nil, return nil) silently lost
// that signal; this test locks the remediation introduced in the
// response-validation follow-up commit.
func TestRawBodyBytes_NilReturnsJSONNullLiteral(t *testing.T) {
	got := rawBodyBytes(nil)
	want := []byte("null")
	if string(got) != string(want) {
		t.Errorf("rawBodyBytes(nil) = %q, want %q", string(got), string(want))
	}
}

func TestRawBodyBytes_EmptyMapReturnsEmptyJSONObject(t *testing.T) {
	got := rawBodyBytes(map[string]any{})
	want := []byte("{}")
	if string(got) != string(want) {
		t.Errorf("rawBodyBytes(map[string]any{}) = %q, want %q", string(got), string(want))
	}
}

// String input → raw UTF-8 bytes (not JSON-quoted). This is the
// load-bearing regression tripwire for the string path: a prior version
// of rawBodyBytes round-tripped strings through json.Marshal and wrapped
// the text in JSON quotes, which hid the original gateway content behind
// a JSON-string literal on .Body. Python preserves raw text on the same
// path; this test locks cross-language parity.
func TestRawBodyBytes_StringReturnsRawBytes(t *testing.T) {
	got := rawBodyBytes("plain text")
	want := []byte("plain text")
	if string(got) != string(want) {
		t.Errorf("rawBodyBytes(%q) = %q, want %q", "plain text", string(got), string(want))
	}
}

func TestRawBodyBytes_EmptyStringReturnsEmptyBytes(t *testing.T) {
	got := rawBodyBytes("")
	want := []byte("")
	if string(got) != string(want) {
		t.Errorf("rawBodyBytes(\"\") = %q, want %q", string(got), string(want))
	}
}

// Go's encoding/json marshals []byte as a base64-encoded JSON string —
// not raw bytes and not a JSON array. "raw" → base64("raw") → "cmF3" →
// quoted `"cmF3"`. This test locks that behaviour so a future refactor
// that reintroduces a []byte special case doesn't silently alter what
// ends up on *ResponseValidationError.Body.
func TestRawBodyBytes_BytesReturnBase64JSONString(t *testing.T) {
	got := rawBodyBytes([]byte("raw"))
	want := []byte(`"cmF3"`)
	if string(got) != string(want) {
		t.Errorf("rawBodyBytes([]byte(%q)) = %q, want %q", "raw", string(got), string(want))
	}
}

// Nested maps must round-trip with sorted keys at every level (Go
// encoding/json default since 1.12). This is the same invariant
// internal/verify.CanonicalJSON relies on for byte-equivalence with the
// TS and Python canonical ports; locking it in errors_test gives us a
// second tripwire independent of the verify pipeline.
func TestRawBodyBytes_NestedMapRoundTrips(t *testing.T) {
	got := rawBodyBytes(map[string]any{"a": map[string]any{"b": "c"}})
	want := []byte(`{"a":{"b":"c"}}`)
	if string(got) != string(want) {
		t.Errorf("rawBodyBytes(nested) = %q, want %q", string(got), string(want))
	}
}

func TestErrorsAs_HTTPError(t *testing.T) {
	err := error(&HTTPError{Status: 401, Message: "nope"})
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("errors.As should succeed")
	}
	if httpErr.Status != 401 {
		t.Errorf("status = %d, want 401", httpErr.Status)
	}
}

func TestErrorsAs_CertificateError(t *testing.T) {
	err := error(&CertificateError{Reason: ReasonMalformed, Message: "bad"})
	var certErr *CertificateError
	if !errors.As(err, &certErr) {
		t.Fatalf("errors.As should succeed")
	}
	if certErr.Reason != ReasonMalformed {
		t.Errorf("reason = %q, want malformed", certErr.Reason)
	}
}
