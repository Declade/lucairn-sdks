package lucairn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Client is the Lucairn gateway client. Construct with New.
//
// Client is safe for concurrent use by multiple goroutines; it reuses a
// single *http.Client under the hood (stdlib-safe per the net/http docs).
type Client struct {
	apiKey           string
	baseURL          string
	timeout          time.Duration
	http             *http.Client
	maxResponseBytes int64
}

// DefaultBaseURL is the hosted gateway for solo-dev tier. Enterprise
// self-hosters must pass WithBaseURL at New-time.
const DefaultBaseURL = "https://gateway.dsaveil.io"

// DefaultTimeout is the default per-call timeout. Matches the TS SDK's
// DEFAULT_TIMEOUT_MS = 30_000.
const DefaultTimeout = 30 * time.Second

// DefaultMaxResponseBytes caps the size of a response body the SDK will
// buffer. 10 MiB — see WithMaxResponseBytes for rationale.
const DefaultMaxResponseBytes int64 = 10 * 1024 * 1024

var apiKeyPattern = regexp.MustCompile(`^dsa_[0-9a-f]{32}$`)

// New constructs a Client. Validates apiKey, baseURL, and timeout up
// front — returns a *ConfigError on any problem.
func New(apiKey string, opts ...Option) (*Client, error) {
	if !apiKeyPattern.MatchString(apiKey) {
		return nil, &ConfigError{
			Message: `invalid apiKey — expected format "dsa_" followed by 32 lowercase hex characters`,
		}
	}

	cfg := clientConfig{
		baseURL:          DefaultBaseURL,
		timeout:          DefaultTimeout,
		maxResponseBytes: DefaultMaxResponseBytes,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	normalized, err := normalizeBaseURL(cfg.baseURL)
	if err != nil {
		return nil, err
	}

	if cfg.timeout <= 0 || math.IsNaN(float64(cfg.timeout)) {
		return nil, &ConfigError{
			Message: fmt.Sprintf("invalid timeout: %v — must be a positive duration", cfg.timeout),
		}
	}

	if cfg.maxResponseBytes <= 0 {
		return nil, &ConfigError{
			Message: fmt.Sprintf("invalid maxResponseBytes: %d — must be a positive int64", cfg.maxResponseBytes),
		}
	}

	httpClient := cfg.http
	if httpClient == nil {
		httpClient = &http.Client{}
	}

	return &Client{
		apiKey:           apiKey,
		baseURL:          normalized,
		timeout:          cfg.timeout,
		http:             httpClient,
		maxResponseBytes: cfg.maxResponseBytes,
	}, nil
}

// BaseURL returns the (possibly normalized) gateway base URL in use.
func (c *Client) BaseURL() string { return c.baseURL }

// Timeout returns the default per-call timeout.
func (c *Client) Timeout() time.Duration { return c.timeout }

// Messages calls POST /api/v1/proxy/messages. The return is a
// MessagesResponse tagged union:
//
//	switch r := resp.(type) {
//	case *ProxySyncResponse:
//	    // sync (200) terminal result — inspect r.Status for COMPLETED / FAILED
//	case *ProxyAcceptedResponse:
//	    // async (202) processing — poll r.StatusURL
//	}
func (c *Client) Messages(ctx context.Context, req MessagesRequest, opts ...CallOption) (MessagesResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, &ConfigError{Message: "failed to marshal request: " + err.Error()}
	}

	status, respBody, err := c.do(ctx, http.MethodPost, "/api/v1/proxy/messages", body, opts)
	if err != nil {
		return nil, err
	}

	// Discriminate by body.status == "processing" (matching TS SDK behaviour).
	if m, ok := respBody.(map[string]any); ok {
		if s, _ := m["status"].(string); s == "processing" {
			var async ProxyAcceptedResponse
			if decodeErr := decodeInto(respBody, &async); decodeErr != nil {
				// 2xx-but-wrong-shape is NOT an HTTP error — dedicated
				// validation type so callers can branch on "transport
				// failed (*HTTPError)" vs "body doesn't look like a
				// ProxyAcceptedResponse (*ResponseValidationError)".
				return nil, &ResponseValidationError{
					Body:    rawBodyBytes(respBody),
					Message: "response failed to deserialize as ProxyAcceptedResponse: " + decodeErr.Error(),
					Err:     decodeErr,
				}
			}
			// Even on a clean json.Unmarshal, Go is permissive on field
			// presence — a body like {"unrelated":"junk"} decodes into a
			// zero-valued *ProxyAcceptedResponse. Enforce the required-field
			// set explicitly so wrong-shape bodies can't sneak through as
			// apparent success.
			if valErr := validateProxyAcceptedResponse(&async); valErr != nil {
				return nil, &ResponseValidationError{
					Body:    rawBodyBytes(respBody),
					Message: "response decoded but " + valErr.Error(),
					Err:     valErr,
				}
			}
			return &async, nil
		}
	}
	var sync ProxySyncResponse
	if decodeErr := decodeInto(respBody, &sync); decodeErr != nil {
		return nil, &ResponseValidationError{
			Body:    rawBodyBytes(respBody),
			Message: "response failed to deserialize as ProxySyncResponse: " + decodeErr.Error(),
			Err:     decodeErr,
		}
	}
	if valErr := validateProxySyncResponse(&sync); valErr != nil {
		return nil, &ResponseValidationError{
			Body:    rawBodyBytes(respBody),
			Message: "response decoded but " + valErr.Error(),
			Err:     valErr,
		}
	}
	_ = status // non-2xx was already handled inside c.do via *HTTPError
	return &sync, nil
}

// GetCertificate calls GET /api/v1/veil/certificate/{requestID}. On a
// 2xx response returns *VeilCertificate. On the gateway's 202 pending
// wrapper (certificate not yet assembled, or unknown requestID — the
// gateway does not distinguish) returns (nil, *HTTPError) with
// Status=202 and Body holding the pending wrapper:
//
//	{ "status": "pending", "retry_after_seconds": 30, "request_id": ..., "message": ... }
//
// Callers branch on errors.As(err, &httpErr) && httpErr.Status == 202.
//
// No auto-verification — chain VerifyCertificate explicitly.
func (c *Client) GetCertificate(ctx context.Context, requestID string, opts ...CallOption) (*VeilCertificate, error) {
	if requestID == "" {
		return nil, &ConfigError{Message: "requestID must be non-empty"}
	}
	// url.PathEscape percent-encodes everything except unreserved chars,
	// defense-in-depth against path injection. The gateway tolerates
	// unencoded slashes but the SDK should never emit raw `..`.
	encoded := url.PathEscape(requestID)
	path := "/api/v1/veil/certificate/" + encoded

	status, respBody, err := c.do(ctx, http.MethodGet, path, nil, opts)
	if err != nil {
		return nil, err
	}

	if status == 202 {
		return nil, &HTTPError{
			Status:  status,
			Body:    respBody,
			Message: "Veil certificate is not yet assembled; retry after the indicated delay",
		}
	}

	var cert VeilCertificate
	if decodeErr := decodeInto(respBody, &cert); decodeErr != nil {
		// 2xx-but-wrong-shape: dedicated validation error, not HTTP error.
		// See ResponseValidationError docstring in errors.go for rationale.
		return nil, &ResponseValidationError{
			Body:    rawBodyBytes(respBody),
			Message: "response body failed to deserialize as VeilCertificate: " + decodeErr.Error(),
			Err:     decodeErr,
		}
	}
	// json.Unmarshal is permissive on field presence — a body like
	// {"unrelated":"junk"} decodes into a zero-valued *VeilCertificate
	// with no error. Explicitly require the fields a genuine Veil cert
	// cannot omit so wrong-shape bodies cannot surface as apparent
	// success with a zero-value *VeilCertificate.
	if valErr := validateVeilCertificate(&cert); valErr != nil {
		return nil, &ResponseValidationError{
			Body:    rawBodyBytes(respBody),
			Message: "response decoded but " + valErr.Error(),
			Err:     valErr,
		}
	}
	_ = status // non-2xx was already handled inside c.do via *HTTPError
	return &cert, nil
}

// validateVeilCertificate enforces the set of fields a genuine Veil
// Certificate MUST carry — zero-value on any of these means the body
// wasn't a cert even though json.Unmarshal accepted it. Kept minimal:
// only fields whose zero value is indisputably wrong. Optional /
// opaque / tier-gated fields (attestation, anchor_status, claims[i]
// internals) are not policed here; downstream VerifyCertificate
// rejects fuller invariants (request_id match, verdict enum, etc.).
//
// Asymmetry note (intentional — do not "align" without reopening the
// locked minimal-required-field-set decision):
//   - This validator enforces the 5 fields the SDK's own signature-
//     verification pipeline needs: certificate_id, request_id,
//     witness_signature, witness_key_id, issued_at. Any zero means
//     VerifyCertificate cannot proceed anyway.
//   - The TypeScript SDK's parseCertificate
//     (ts/src/verify-certificate/parse.ts) is stricter — it also rejects
//     missing protocol_version, claims (as an array), and verification
//     (as an object). The TS SDK does this because TS has no equivalent
//     of Go's downstream VerifyCertificate-gated protocol_version check
//     and because its DIY parser has no Pydantic-like framework to lean
//     on.
//   - Future maintainers: if you find yourself tempted to widen this Go
//     validator to match TS, re-open the "minimal required-field set"
//     locked decision first. Widening means callers who were getting a
//     silently-zero-valued struct start getting ResponseValidationError
//     — behaviour change the locked decision deliberately avoided.
func validateVeilCertificate(c *VeilCertificate) error {
	if c.CertificateID == "" {
		return fmt.Errorf("VeilCertificate.certificate_id is empty")
	}
	if c.RequestID == "" {
		return fmt.Errorf("VeilCertificate.request_id is empty")
	}
	if c.WitnessSignature == "" {
		return fmt.Errorf("VeilCertificate.witness_signature is empty")
	}
	if c.WitnessKeyID == "" {
		return fmt.Errorf("VeilCertificate.witness_key_id is empty")
	}
	if c.IssuedAt == "" {
		return fmt.Errorf("VeilCertificate.issued_at is empty")
	}
	return nil
}

// validateProxySyncResponse enforces the minimum field set for a sync
// (200) terminal result — Status discriminates COMPLETED vs FAILED and
// ModelUsed names which provider model served the request. LatencyMs is
// not required (the gateway may legitimately emit 0 on sub-ms paths).
func validateProxySyncResponse(s *ProxySyncResponse) error {
	if s.Status == "" {
		return fmt.Errorf("ProxySyncResponse.status is empty")
	}
	if s.ModelUsed == "" {
		return fmt.Errorf("ProxySyncResponse.model_used is empty")
	}
	return nil
}

// validateProxyAcceptedResponse enforces the minimum field set for an
// async (202) processing receipt — JobID + RequestID + StatusURL are all
// needed for the caller to poll. The Status field is NOT re-checked
// here: the async branch is only entered after the caller gated on
// m["status"].(string) == "processing", so by the time this validator
// runs the status is guaranteed populated.
func validateProxyAcceptedResponse(a *ProxyAcceptedResponse) error {
	if a.JobID == "" {
		return fmt.Errorf("ProxyAcceptedResponse.job_id is empty")
	}
	if a.RequestID == "" {
		return fmt.Errorf("ProxyAcceptedResponse.request_id is empty")
	}
	if a.StatusURL == "" {
		return fmt.Errorf("ProxyAcceptedResponse.status_url is empty")
	}
	return nil
}

// rawBodyBytes re-serializes the transport-parsed body back into raw
// bytes for *ResponseValidationError.Body.
//
// Path by input type:
//   - string (non-JSON 2xx body the transport layer stored raw): returned
//     as the underlying UTF-8 bytes verbatim. Re-encoding through
//     json.Marshal would wrap the text in JSON quotes, which would hide
//     the original gateway content behind a JSON-string literal on the
//     caller's diagnostic .Body. Python preserves the raw text on this
//     path too; this matches that behaviour.
//   - nil (the parsed form of a literal JSON null response):
//     json.Marshal(nil) → []byte("null"). Preserves the "gateway sent
//     null" signal so the diagnostic .Body never looks like "SDK forgot
//     to populate it."
//   - everything else (maps, slices, numbers, bools from json.Unmarshal,
//     plus []byte which Go marshals as base64): round-trips through
//     json.Marshal for a predictable JSON encoding on .Body.
//     json.Marshal on a value produced by json.Unmarshal cannot fail in
//     practice (channels/funcs/cycles are the only rejection cases, and
//     none originate from unmarshal), so the error branch is
//     defensive-dead but kept for the invariant.
func rawBodyBytes(body any) []byte {
	if s, ok := body.(string); ok {
		return []byte(s)
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil
	}
	return b
}

// VerifyCertificate is the method form of the package-level
// VerifyCertificate function. Useful when a caller wants a single object
// holding both transport and verify.
func (c *Client) VerifyCertificate(cert any, keys VerifyCertificateKeys) (*VerifyCertificateResult, error) {
	return VerifyCertificate(cert, keys)
}

// -- Transport primitive --------------------------------------------------

// do executes a single HTTP request. Returns (status, parsedBody, error).
//
// Body is parsed as JSON when the response text is non-empty; otherwise
// returned as the raw string. Non-2xx status codes return (_, _, *HTTPError).
// Context cancellation / deadline exceeded returns (_, _, *TimeoutError)
// or (_, _, *NetworkError) depending on which fired. The 2xx happy-path
// body passes through without shape validation — thin-transport rule.
func (c *Client) do(
	ctx context.Context,
	method, path string,
	body []byte,
	opts []CallOption,
) (int, any, error) {
	cc := callConfig{}
	for _, opt := range opts {
		opt(&cc)
	}
	timeout := c.timeout
	if cc.timeout > 0 {
		timeout = cc.timeout
	} else if cc.timeout < 0 {
		return 0, nil, &ConfigError{
			Message: fmt.Sprintf("invalid call timeout: %v — must be a positive duration", cc.timeout),
		}
	}

	// Layer the timeout on top of whatever context the caller passed.
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	u := c.baseURL + path
	var reqBody io.Reader
	if body != nil {
		reqBody = bytes.NewReader(body)
	}
	httpReq, err := http.NewRequestWithContext(callCtx, method, u, reqBody)
	if err != nil {
		return 0, nil, &NetworkError{
			Message: "failed to build request: " + err.Error(),
			Err:     err,
		}
	}

	// Caller headers first, SDK-owned last.
	for k, v := range cc.headers {
		httpReq.Header.Set(k, v)
	}
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("content-type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		// Distinguish timeout from caller cancel from network error.
		// ctx.Err() is the source-of-truth for why the request failed.
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			return 0, nil, &TimeoutError{
				Message: fmt.Sprintf("request timed out after %s", timeout),
				Err:     err,
			}
		}
		if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			return 0, nil, &NetworkError{
				Message: "request canceled",
				Err:     err,
			}
		}
		return 0, nil, &NetworkError{
			Message: "request failed: " + err.Error(),
			Err:     err,
		}
	}
	defer resp.Body.Close()

	// Cap the read at maxResponseBytes + 1 so we can distinguish "exactly cap"
	// from "exceeded cap" without buffering the entire pathological body.
	limitedReader := io.LimitReader(resp.Body, c.maxResponseBytes+1)
	respBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return resp.StatusCode, nil, &NetworkError{
			Message: "failed to read response body: " + err.Error(),
			Err:     err,
		}
	}
	if int64(len(respBytes)) > c.maxResponseBytes {
		// Preserve the prefix we already buffered — truncated to the cap
		// for bounded memory. Callers inspecting the over-cap error can
		// see how the gateway was starting to respond, useful for
		// diagnosing misbehaving endpoints.
		partial := respBytes[:c.maxResponseBytes]
		// Cap-overflow on a 2xx means "gateway replied with apparent success
		// but the body we received is not consumable" — route via
		// *ResponseValidationError so the "*HTTPError never fires on 2xx"
		// invariant holds uniformly. Non-2xx over-cap still falls through
		// to *HTTPError below because the caller genuinely saw a transport
		// error AND an oversized body.
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp.StatusCode, nil, &ResponseValidationError{
				Body:    partial,
				Message: fmt.Sprintf("response body exceeded MaxResponseBytes cap of %d", c.maxResponseBytes),
			}
		}
		return resp.StatusCode, nil, &HTTPError{
			Status:  resp.StatusCode,
			Body:    partial,
			Message: fmt.Sprintf("response body exceeded MaxResponseBytes cap of %d", c.maxResponseBytes),
		}
	}

	var parsed any
	text := string(respBytes)
	if len(respBytes) > 0 {
		// Try JSON parse; on failure keep the raw text.
		var jsonVal any
		if json.Unmarshal(respBytes, &jsonVal) == nil {
			parsed = jsonVal
		} else {
			parsed = text
		}
	} else {
		parsed = text
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return resp.StatusCode, parsed, &HTTPError{
			Status:  resp.StatusCode,
			Body:    parsed,
			Message: fmt.Sprintf("Lucairn request failed: %d %s", resp.StatusCode, resp.Status),
		}
	}

	return resp.StatusCode, parsed, nil
}

// decodeInto round-trips a parsed-JSON any through json.Marshal/Unmarshal
// into dst. Used to coerce the untyped transport body into a typed
// response struct. A bit wasteful (re-marshal) but keeps the transport
// primitive free of generics and type-specific logic.
func decodeInto(body any, dst any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}

// normalizeBaseURL parses raw, confirms http/https scheme + non-empty
// host, rejects http:// outside loopback / mDNS-local hosts to prevent
// cleartext api-key leakage, and strips trailing slashes.
func normalizeBaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", &ConfigError{Message: "invalid baseURL: " + err.Error()}
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", &ConfigError{
			Message: fmt.Sprintf("baseURL must use http or https, got: %q", u.Scheme),
		}
	}
	if u.Host == "" {
		return "", &ConfigError{Message: "baseURL must have a host: " + raw}
	}
	if u.Scheme == "http" {
		host := strings.ToLower(u.Hostname())
		loopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
		if !loopback && !strings.HasSuffix(host, ".local") {
			return "", &ConfigError{
				Message: fmt.Sprintf(
					"baseURL must use https:// for non-loopback hosts; got http://%s",
					host,
				),
			}
		}
	}
	return strings.TrimRight(raw, "/"), nil
}
