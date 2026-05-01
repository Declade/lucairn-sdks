package lucairn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newMockedClient returns a client whose baseURL points at httptest.Server's
// URL. Use the returned cleanup func via defer.
func newMockedClient(t *testing.T, handler http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(handler)
	c, err := New(validAPIKey, WithBaseURL(server.URL))
	if err != nil {
		server.Close()
		t.Fatalf("New: %v", err)
	}
	return c, server
}

// -- Happy path ----------------------------------------------------------

func TestGetCertificate_HappyPath(t *testing.T) {
	cert := loadFixture(t, "cert-valid-anchored.json")
	requestID := cert["request_id"].(string)

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/veil/certificate/"+requestID {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != validAPIKey {
			t.Errorf("x-api-key missing or wrong")
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(cert)
	}

	c, server := newMockedClient(t, handler)
	defer server.Close()

	got, err := c.GetCertificate(context.Background(), requestID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.CertificateID != cert["certificate_id"].(string) {
		t.Errorf("CertificateID = %q", got.CertificateID)
	}
	if got.WitnessKeyID != "witness_v1" {
		t.Errorf("WitnessKeyID = %q", got.WitnessKeyID)
	}
}

// -- 202 pending ---------------------------------------------------------

func TestGetCertificate_PendingRaisesHTTPErrorWith202(t *testing.T) {
	pendingBody := map[string]any{
		"status":              "pending",
		"request_id":          "req_pending_0001",
		"message":             "Veil certificate is not ready yet.",
		"retry_after_seconds": 30,
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(pendingBody)
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(context.Background(), "req_pending_0001")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want HTTPError, got %T (%v)", err, err)
	}
	if httpErr.Status != 202 {
		t.Errorf("status = %d, want 202", httpErr.Status)
	}
	body, ok := httpErr.Body.(map[string]any)
	if !ok {
		t.Fatalf("body type = %T, want map[string]any", httpErr.Body)
	}
	if s, _ := body["status"].(string); s != "pending" {
		t.Errorf("body.status = %v", body["status"])
	}
	if r, _ := body["retry_after_seconds"].(float64); r != 30 {
		t.Errorf("body.retry_after_seconds = %v", body["retry_after_seconds"])
	}
}

// -- HTTP error mapping --------------------------------------------------

func TestGetCertificate_MapsStatusAndCode(t *testing.T) {
	cases := []struct {
		status int
		code   string
	}{
		{401, "missing_api_key"},
		{401, "invalid_api_key"},
		{403, "tier_insufficient"},
		{404, "veil_not_configured"},
		{502, "upstream_error"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			body := map[string]any{
				"error": map[string]any{
					"code":    tc.code,
					"message": "test " + tc.code,
				},
			}
			handler := func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-type", "application/json")
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(body)
			}
			c, server := newMockedClient(t, handler)
			defer server.Close()

			_, err := c.GetCertificate(context.Background(), "req_err_0001")
			var httpErr *HTTPError
			if !errors.As(err, &httpErr) {
				t.Fatalf("want HTTPError, got %T", err)
			}
			if httpErr.Status != tc.status {
				t.Errorf("status = %d, want %d", httpErr.Status, tc.status)
			}
			b, _ := httpErr.Body.(map[string]any)
			e, _ := b["error"].(map[string]any)
			if e["code"] != tc.code {
				t.Errorf("body.error.code = %v", e["code"])
			}
		})
	}
}

func TestGetCertificate_503_RetryAfterInBody(t *testing.T) {
	body := map[string]any{
		"error": map[string]any{
			"code":                "veil_unavailable",
			"message":             "Veil Witness is temporarily unavailable.",
			"retry_after_seconds": 30,
		},
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(503)
		_ = json.NewEncoder(w).Encode(body)
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(context.Background(), "req_unavail")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want HTTPError, got %T", err)
	}
	if httpErr.Status != 503 {
		t.Errorf("status = %d", httpErr.Status)
	}
	b, _ := httpErr.Body.(map[string]any)
	e, _ := b["error"].(map[string]any)
	if r, _ := e["retry_after_seconds"].(float64); r != 30 {
		t.Errorf("retry_after_seconds = %v", e["retry_after_seconds"])
	}
}

// -- Transport errors ----------------------------------------------------

func TestGetCertificate_NetworkErrorWrapsToNetworkError(t *testing.T) {
	// Closed server → connection refused.
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()

	c, err := New(validAPIKey, WithBaseURL(url))
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetCertificate(context.Background(), "req_network_0001")
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("want NetworkError, got %T (%v)", err, err)
	}
	// Should NOT also be an HTTPError.
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		t.Error("should not also be HTTPError")
	}
}

// -- Timeout + cancellation ---------------------------------------------

func TestGetCertificate_PerCallTimeout(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		// Bounded wait — r.Context() cancellation propagation can lag due
		// to keep-alive/transport pooling; the client-side deadline fires
		// well before this bound.
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(
		context.Background(),
		"req_slow_0001",
		WithCallTimeout(10*time.Millisecond),
	)
	var timeoutErr *TimeoutError
	if !errors.As(err, &timeoutErr) {
		t.Fatalf("want TimeoutError, got %T (%v)", err, err)
	}
}

func TestGetCertificate_CallerCancelPropagates(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel

	_, err := c.GetCertificate(ctx, "req_cancel_0001")
	// Caller cancel surfaces as NetworkError with ctx.Canceled unwrapped.
	var netErr *NetworkError
	if !errors.As(err, &netErr) {
		t.Fatalf("want NetworkError, got %T", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) should be true")
	}
}

// -- Path encoding ------------------------------------------------------

func TestGetCertificate_PercentEncodesReservedChars(t *testing.T) {
	cert := loadFixture(t, "cert-valid-anchored.json")
	var observedPath string
	handler := func(w http.ResponseWriter, r *http.Request) {
		// Grab the raw request URI to see the encoded form (r.URL.Path is
		// decoded by net/http's mux). RawPath preserves encoding.
		observedPath = r.URL.EscapedPath()
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(cert)
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(context.Background(), "req/weird id?")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(observedPath, "%2F") || !strings.Contains(observedPath, "%20") {
		t.Errorf("encoded path missing %%2F / %%20: %q", observedPath)
	}
	if strings.Contains(observedPath, "req/weird id?") {
		t.Errorf("encoded path should not contain raw form: %q", observedPath)
	}
}

func TestGetCertificate_RejectsEmptyRequestID(t *testing.T) {
	c, err := New(validAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetCertificate(context.Background(), "")
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want ConfigError, got %T", err)
	}
}

// -- MaxResponseBytes enforcement ---------------------------------------

func TestGetCertificate_2xxOverCap_RaisesResponseValidationError(t *testing.T) {
	big := "PREFIX_MARKER_" + strings.Repeat("x", 1024)
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		_, _ = w.Write([]byte(big))
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	c, err := New(
		validAPIKey,
		WithBaseURL(server.URL),
		WithMaxResponseBytes(256), // deliberately small
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetCertificate(context.Background(), "req_big")
	var vErr *ResponseValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("want *ResponseValidationError, got %T (%v)", err, err)
	}
	if !strings.Contains(vErr.Message, "MaxResponseBytes") {
		t.Errorf("message should mention cap: %q", vErr.Message)
	}
	// Body preservation: accumulated prefix must land on Body (truncated
	// to the cap, so the marker prefix survives).
	if len(vErr.Body) == 0 {
		t.Errorf("Body should carry the accumulated prefix, not nil")
	}
	if int64(len(vErr.Body)) > 256 {
		t.Errorf("Body should be truncated to the cap, got %d bytes", len(vErr.Body))
	}
	if !strings.Contains(string(vErr.Body), "PREFIX_MARKER_") {
		t.Errorf("Body should contain the prefix marker: %q", string(vErr.Body))
	}
	// Invariant: must NOT also be *HTTPError on a 2xx over-cap.
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		t.Errorf("must not also be *HTTPError on a 2xx over-cap")
	}
}

func TestGetCertificate_Non2xxOverCap_RaisesHTTPError(t *testing.T) {
	// Cap-overflow on a non-2xx keeps *HTTPError — the transport status
	// is the dominant signal. Gateway that returns 502 with an oversized
	// body should surface as 502, not wrong-shape. Body preservation
	// applies to this path too so callers can still see what the gateway
	// was starting to send.
	big := "ERROR_MARKER_" + strings.Repeat("x", 1024)
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		w.WriteHeader(502)
		_, _ = w.Write([]byte(big))
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	c, err := New(
		validAPIKey,
		WithBaseURL(server.URL),
		WithMaxResponseBytes(256),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetCertificate(context.Background(), "req_big_err")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want *HTTPError, got %T (%v)", err, err)
	}
	if httpErr.Status != 502 {
		t.Errorf("status = %d", httpErr.Status)
	}
	bodyBytes, ok := httpErr.Body.([]byte)
	if !ok {
		t.Fatalf("Body should be []byte on over-cap path, got %T", httpErr.Body)
	}
	if !strings.Contains(string(bodyBytes), "ERROR_MARKER_") {
		t.Errorf("Body should contain the error marker: %q", string(bodyBytes))
	}
}

func TestGetCertificate_ResponseUnderCap_Accepted(t *testing.T) {
	cert := loadFixture(t, "cert-valid-anchored.json")
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(cert)
	}
	server := httptest.NewServer(http.HandlerFunc(handler))
	defer server.Close()
	c, err := New(
		validAPIKey,
		WithBaseURL(server.URL),
		WithMaxResponseBytes(1024*1024), // 1 MiB, ample
	)
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.GetCertificate(context.Background(), cert["request_id"].(string))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if got.CertificateID != cert["certificate_id"].(string) {
		t.Errorf("CertificateID mismatch")
	}
}

// -- Header merge (SDK-owned keys win) ----------------------------------

func TestGetCertificate_CallerHeadersMerged_SDKKeysWin(t *testing.T) {
	cert := loadFixture(t, "cert-valid-anchored.json")
	var observedAPIKey, observedCorr, observedContentType string
	handler := func(w http.ResponseWriter, r *http.Request) {
		observedAPIKey = r.Header.Get("x-api-key")
		observedCorr = r.Header.Get("x-correlation-id")
		observedContentType = r.Header.Get("content-type")
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(cert)
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(
		context.Background(),
		"req_headers",
		WithCallHeader("x-correlation-id", "corr_abc"),
		WithCallHeader("x-api-key", "dsa_"+strings.Repeat("f", 32)),
		WithCallHeader("content-type", "text/plain"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if observedCorr != "corr_abc" {
		t.Errorf("x-correlation-id = %q", observedCorr)
	}
	if observedAPIKey != validAPIKey {
		t.Errorf("x-api-key = %q, want SDK-owned %q", observedAPIKey, validAPIKey)
	}
	if observedContentType != "application/json" {
		t.Errorf("content-type = %q, want SDK-owned", observedContentType)
	}
}

// -- Malformed 200 body -------------------------------------------------

func TestGetCertificate_Malformed200_NonJSON(t *testing.T) {
	// Non-JSON 2xx body fails decodeInto (json.Marshal + Unmarshal round
	// trip chokes on a non-JSON string) and surfaces via the dedicated
	// *ResponseValidationError — NOT *HTTPError, which is reserved for
	// non-2xx transport failures.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		_, _ = w.Write([]byte("not json at all"))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(context.Background(), "req_malformed_0001")
	var vErr *ResponseValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("want *ResponseValidationError, got %T (%v)", err, err)
	}
	// rawBodyBytes preserves string inputs verbatim (no JSON re-encoding)
	// so a non-JSON 2xx body surfaces on .Body as the exact raw bytes the
	// gateway sent. Matches Python's raw-text preservation on the same
	// path. The equality assertion below locks the raw form; an earlier
	// implementation wrapped the text in JSON quotes and callers saw a
	// `"..."` literal instead of the original content.
	if string(vErr.Body) != "not json at all" {
		t.Errorf("Body = %q, want %q (raw, not JSON-quoted)", string(vErr.Body), "not json at all")
	}
	// Invariant: must NOT also be an *HTTPError — semantic distinction.
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		t.Errorf("should not also be *HTTPError: %v", httpErr)
	}
	// Still satisfies the base Error interface so callers doing blanket
	// lucairn.Error type switches still catch it.
	var base Error
	if !errors.As(err, &base) {
		t.Errorf("should satisfy lucairn.Error interface")
	}
	// Underlying json error preserved via Unwrap.
	if vErr.Err == nil {
		t.Errorf("Err should wrap the underlying json error")
	}
}

func TestGetCertificate_PlainText2xx_PreservesRawText(t *testing.T) {
	// Regression guard for the string-path fix in rawBodyBytes: a gateway
	// that returns a plain-text 2xx body (e.g. an upstream error leaking
	// through as text/plain, or a misrouted request hitting a static
	// error page) must surface on .Body as the exact raw bytes — not a
	// JSON-quoted literal. This was the wrong-behaviour Codex caught on
	// the 13-commit stack review.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		_, _ = w.Write([]byte("service unavailable"))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(context.Background(), "req_plain")
	var vErr *ResponseValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("want *ResponseValidationError, got %T (%v)", err, err)
	}
	if string(vErr.Body) != "service unavailable" {
		t.Errorf("Body = %q, want %q (raw, not JSON-quoted)", string(vErr.Body), "service unavailable")
	}
	// Leading byte must NOT be `"` — that would mean json.Marshal wrapped
	// the text, reintroducing the regression.
	if len(vErr.Body) > 0 && vErr.Body[0] == '"' {
		t.Errorf("Body should not be JSON-quoted: %q", string(vErr.Body))
	}
}

func TestGetCertificate_LiteralNullBody_PreservesNullSignal(t *testing.T) {
	// A 2xx response with a literal JSON null body parses cleanly (Go
	// nil), fails required-field validation, and must surface as
	// *ResponseValidationError with Body = []byte("null") — not nil.
	// This distinguishes "gateway sent null" from "SDK forgot to
	// populate .Body" in the caller's diagnostic output.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte("null"))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	cert, err := c.GetCertificate(context.Background(), "req_null")
	if cert != nil {
		t.Errorf("expected nil cert on null-body failure")
	}
	var vErr *ResponseValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("want *ResponseValidationError, got %T (%v)", err, err)
	}
	if string(vErr.Body) != "null" {
		t.Errorf("Body = %q, want %q", string(vErr.Body), "null")
	}
}

func TestGetCertificate_Non2xx_UsesHTTPErrorNotResponseValidation(t *testing.T) {
	// Invariant: non-2xx MUST still raise *HTTPError, not
	// *ResponseValidationError. The new class must never fire for
	// transport-level failures.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(404)
		_, _ = w.Write([]byte(`{"error": {"code": "veil_not_configured"}}`))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificate(context.Background(), "req_missing")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want *HTTPError, got %T", err)
	}
	if httpErr.Status != 404 {
		t.Errorf("status = %d", httpErr.Status)
	}
	var vErr *ResponseValidationError
	if errors.As(err, &vErr) {
		t.Errorf("should not also be *ResponseValidationError")
	}
}

func TestGetCertificate_Malformed200_MissingRequiredFields_RaisesResponseValidation(t *testing.T) {
	// Go's json.Unmarshal is permissive on missing fields (zero-values
	// them) — so the decode itself succeeds on a valid JSON object
	// lacking cert fields. Without explicit required-field validation
	// the SDK would return a zero-value *VeilCertificate as apparent
	// success, leaving the burden to VerifyCertificate. The SDK now
	// enforces the required-field set in validateVeilCertificate(),
	// so wrong-shape 2xx bodies surface as *ResponseValidationError
	// with the raw body preserved.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"unrelated": "junk"}`))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	cert, err := c.GetCertificate(context.Background(), "req_partial_0001")
	if cert != nil {
		t.Errorf("expected nil cert on required-field failure, got %+v", cert)
	}
	var vErr *ResponseValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("want *ResponseValidationError, got %T (%v)", err, err)
	}
	if !strings.Contains(vErr.Message, "certificate_id") {
		t.Errorf("message should name the missing field: %q", vErr.Message)
	}
	if len(vErr.Body) == 0 {
		t.Errorf("Body should be non-empty (raw server bytes)")
	}
	if !strings.Contains(string(vErr.Body), "unrelated") {
		t.Errorf("Body should contain the raw response: %q", string(vErr.Body))
	}
	// Invariant: still not an *HTTPError.
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		t.Errorf("must not also be *HTTPError")
	}
	// Err wraps the underlying validation cause for errors.Is/As walks.
	if vErr.Err == nil {
		t.Errorf("Err should wrap the validation cause")
	}
}
