// Package lucairn is the Go client for Lucairn — privacy-preserving AI
// infrastructure.
//
// See https://lucairn.eu for product documentation and the TypeScript SDK at
// https://github.com/Declade/lucairn-sdks/tree/main/ts for cross-language
// behaviour parity notes.
package lucairn

import (
	"fmt"
)

// Error is the base sentinel for errors returned by this package. All
// concrete error types below satisfy this interface, so callers can check
// "did this come from the SDK?" with errors.As(err, &lucairn.Error(nil))-
// style patterns. Direct errors.As to the concrete types for structured
// inspection (status, reason, etc.).
type Error interface {
	error
	lucairnError()
}

// ConfigError is returned when a constructor / per-call option is invalid.
// Examples: malformed apiKey, non-https baseURL in production, non-finite
// timeout. These are caller-correctable.
type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return "lucairn: " + e.Message
}

func (e *ConfigError) lucairnError() {}

// HTTPError is returned when the gateway returns a non-2xx response, or a
// 202 pending wrapper on GetCertificate. Status is the real HTTP status
// code. Body is the parsed JSON body (map/slice/primitive) when the
// response text parses as JSON, otherwise the raw text as string.
//
// Callers branch on err.Status to distinguish auth errors (401/403),
// transient errors (502/503), or a pending certificate
// (202 with body["status"] == "pending").
type HTTPError struct {
	Status  int
	Body    any
	Message string
	Err     error
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("lucairn: %s (status=%d)", e.Message, e.Status)
}

func (e *HTTPError) Unwrap() error { return e.Err }

func (e *HTTPError) lucairnError() {}

// TimeoutError is returned when a request exceeds its per-call or
// client-default timeout, or the caller's context deadline fires first.
// Distinct from a caller-initiated cancel, which surfaces the context's
// own Canceled error (wrapped in a NetworkError so callers can still
// errors.Is(err, context.Canceled)).
type TimeoutError struct {
	Message string
	Err     error
}

func (e *TimeoutError) Error() string {
	return "lucairn: " + e.Message
}

func (e *TimeoutError) Unwrap() error { return e.Err }

func (e *TimeoutError) lucairnError() {}

// NetworkError wraps generic transport failures (connection refused,
// TLS handshake, canceled context, etc.) that are not structured HTTP
// error responses from the gateway.
type NetworkError struct {
	Message string
	Err     error
}

func (e *NetworkError) Error() string {
	return "lucairn: " + e.Message
}

func (e *NetworkError) Unwrap() error { return e.Err }

func (e *NetworkError) lucairnError() {}

// VerifyCertificateFailureReason names a concrete failure mode of
// VerifyCertificate. The five values here mirror the TS SDK's
// VerifyCertificateFailureReason literal union one-for-one.
type VerifyCertificateFailureReason string

const (
	ReasonMalformed                   VerifyCertificateFailureReason = "malformed"
	ReasonUnsupportedProtocolVersion  VerifyCertificateFailureReason = "unsupported_protocol_version"
	ReasonWitnessMismatch             VerifyCertificateFailureReason = "witness_mismatch"
	ReasonWitnessSignatureMissing     VerifyCertificateFailureReason = "witness_signature_missing"
	ReasonInvalidSignature            VerifyCertificateFailureReason = "invalid_signature"
)

// ResponseValidationError is returned when a 2xx gateway response fails
// to deserialize into the SDK's declared response type (either
// json.Unmarshal fails, or the resulting struct has missing required
// fields surfaced via a follow-up check).
//
// Distinct from *HTTPError, which is reserved for non-2xx gateway
// responses and the 202 pending wrapper on GetCertificate. A
// ResponseValidationError means "the gateway replied with apparent
// success, but the body we got doesn't fit the declared type" —
// typically a gateway bug or version skew, not a transport failure.
//
// Matches aws-sdk-go-v2's *smithy.DeserializationError and
// kubernetes/client-go's runtime-decode error shape: (nil, err) on any
// decode failure, with the underlying error wrapped via Unwrap() for
// errors.Is / errors.As.
type ResponseValidationError struct {
	Body    []byte
	Message string
	Err     error
}

func (e *ResponseValidationError) Error() string {
	return "lucairn: " + e.Message
}

func (e *ResponseValidationError) Unwrap() error { return e.Err }

func (e *ResponseValidationError) lucairnError() {}

// CertificateError is returned by VerifyCertificate when verification
// fails. Reason names the specific failure mode. CertificateID is lifted
// from cert.CertificateID for error-context logging when available.
//
// SECURITY NOTE: on all failure paths, CertificateID is UNVERIFIED —
// the witness signature has not yet (or failed to) verify by the time
// this ID is attached. An attacker or malformed cert can set any string
// here. Consumers logging this field should treat it as untrusted input
// (escape / truncate / bound length). Only on the success return path
// (VerifyCertificateResult.CertificateID) is this value covered by the
// witness signature.
type CertificateError struct {
	Reason        VerifyCertificateFailureReason
	CertificateID string
	Message       string
	Err           error
}

func (e *CertificateError) Error() string {
	if e.CertificateID != "" {
		return fmt.Sprintf("lucairn: %s (reason=%s, certificate_id=%q)", e.Message, e.Reason, e.CertificateID)
	}
	return fmt.Sprintf("lucairn: %s (reason=%s)", e.Message, e.Reason)
}

func (e *CertificateError) Unwrap() error { return e.Err }

func (e *CertificateError) lucairnError() {}
