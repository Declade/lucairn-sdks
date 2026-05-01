package lucairn

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func basicMessagesRequest() MessagesRequest {
	maxTokens := 256
	return MessagesRequest{
		PromptTemplate: "hello {customer}",
		Context:        map[string]string{"customer": "Ada"},
		Model:          "claude-opus-4-7",
		MaxTokens:      &maxTokens,
	}
}

// -- Happy path: sync --------------------------------------------------

func TestMessages_SyncCompleted(t *testing.T) {
	body := map[string]any{
		"status":     "JOB_STATUS_COMPLETED",
		"model_used": "claude-opus-4-7",
		"latency_ms": 1234,
		"result":     map[string]any{"content": "Hello, Ada."},
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %q", r.Method)
		}
		if r.URL.Path != "/api/v1/proxy/messages" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != validAPIKey {
			t.Error("x-api-key header missing")
		}
		if r.Header.Get("content-type") != "application/json" {
			t.Error("content-type header missing")
		}
		reqBody, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(reqBody), `"prompt_template":"hello {customer}"`) {
			t.Errorf("request body missing prompt_template: %s", string(reqBody))
		}
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	resp, err := c.Messages(context.Background(), basicMessagesRequest())
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	sync, ok := resp.(*ProxySyncResponse)
	if !ok {
		t.Fatalf("want *ProxySyncResponse, got %T", resp)
	}
	if sync.Status != "JOB_STATUS_COMPLETED" {
		t.Errorf("status = %q", sync.Status)
	}
	if sync.ModelUsed != "claude-opus-4-7" {
		t.Errorf("model_used = %q", sync.ModelUsed)
	}
	if sync.LatencyMs != 1234 {
		t.Errorf("latency_ms = %d", sync.LatencyMs)
	}
}

func TestMessages_SyncFailed(t *testing.T) {
	body := map[string]any{
		"status":        "JOB_STATUS_FAILED",
		"model_used":    "claude-opus-4-7",
		"latency_ms":    42,
		"error_message": "upstream model timeout",
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	resp, err := c.Messages(context.Background(), basicMessagesRequest())
	if err != nil {
		t.Fatal(err)
	}
	sync, ok := resp.(*ProxySyncResponse)
	if !ok {
		t.Fatalf("want *ProxySyncResponse, got %T", resp)
	}
	if sync.Status != "JOB_STATUS_FAILED" {
		t.Errorf("status = %q", sync.Status)
	}
	if sync.ErrorMessage != "upstream model timeout" {
		t.Errorf("error_message = %q", sync.ErrorMessage)
	}
}

// -- Async 202 discriminator ---------------------------------------------

func TestMessages_Async202ReturnsAcceptedResponse(t *testing.T) {
	body := map[string]any{
		"status":     "processing",
		"job_id":     "job_abc",
		"request_id": "req_xyz",
		"status_url": "https://gateway.example.com/jobs/job_abc",
		"veil": map[string]any{
			"status":          "pending",
			"certificate_url": "https://gateway.example.com/api/v1/veil/certificate/req_xyz",
			"summary_url":     "https://gateway.example.com/api/v1/veil/certificate/req_xyz/summary",
		},
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(body)
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	resp, err := c.Messages(context.Background(), basicMessagesRequest())
	if err != nil {
		t.Fatal(err)
	}
	async, ok := resp.(*ProxyAcceptedResponse)
	if !ok {
		t.Fatalf("want *ProxyAcceptedResponse, got %T", resp)
	}
	if async.Status != "processing" {
		t.Errorf("status = %q", async.Status)
	}
	if async.JobID != "job_abc" {
		t.Errorf("job_id = %q", async.JobID)
	}
	if async.RequestID != "req_xyz" {
		t.Errorf("request_id = %q", async.RequestID)
	}
	if async.Veil == nil || async.Veil.Status != "pending" {
		t.Errorf("veil.status missing: %+v", async.Veil)
	}
}

// -- Error mapping ------------------------------------------------------

func TestMessages_401RaisesHTTPError(t *testing.T) {
	body := map[string]any{
		"error": map[string]any{"code": "invalid_api_key", "message": "no"},
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(body)
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.Messages(context.Background(), basicMessagesRequest())
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want HTTPError, got %T", err)
	}
	if httpErr.Status != 401 {
		t.Errorf("status = %d", httpErr.Status)
	}
}

// -- Per-call options ---------------------------------------------------

func TestMessages_PerCallHeadersMerge_SDKWins(t *testing.T) {
	var observedAPI, observedCorr string
	body := map[string]any{
		"status":     "JOB_STATUS_COMPLETED",
		"model_used": "x",
		"latency_ms": 1,
	}
	handler := func(w http.ResponseWriter, r *http.Request) {
		observedAPI = r.Header.Get("x-api-key")
		observedCorr = r.Header.Get("x-correlation-id")
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(body)
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.Messages(
		context.Background(),
		basicMessagesRequest(),
		WithCallHeader("x-correlation-id", "corr_abc"),
		WithCallHeader("x-api-key", "dsa_"+strings.Repeat("f", 32)),
	)
	if err != nil {
		t.Fatal(err)
	}
	if observedCorr != "corr_abc" {
		t.Errorf("x-correlation-id = %q", observedCorr)
	}
	if observedAPI != validAPIKey {
		t.Errorf("x-api-key = %q, want SDK-owned", observedAPI)
	}
}

func TestMessages_PerCallTimeoutOverrides(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		// Bounded wait — server-side r.Context() cancellation propagation
		// can lag depending on keep-alive / transport pool state. The
		// client-side deadline fires long before this bound, producing the
		// TimeoutError we assert on.
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.Messages(
		context.Background(),
		basicMessagesRequest(),
		WithCallTimeout(10*time.Millisecond),
	)
	var timeoutErr *TimeoutError
	if !errors.As(err, &timeoutErr) {
		t.Fatalf("want TimeoutError, got %T", err)
	}
}

// -- Malformed 200 body -------------------------------------------------

func TestMessages_Malformed200_PresentStatusButMissingModel_RaisesResponseValidation(t *testing.T) {
	// A body with only `status` set — json.Unmarshal succeeds but
	// ProxySyncResponse is missing its required `model_used` field.
	// validateProxySyncResponse rejects; caller gets
	// *ResponseValidationError rather than a bogus zero-valued struct
	// masquerading as apparent success.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"status": "JOB_STATUS_COMPLETED"}`))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	resp, err := c.Messages(context.Background(), basicMessagesRequest())
	if resp != nil {
		t.Errorf("expected nil resp on required-field failure")
	}
	var vErr *ResponseValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("want *ResponseValidationError, got %T (%v)", err, err)
	}
	if !strings.Contains(vErr.Message, "model_used") {
		t.Errorf("message should name the missing field: %q", vErr.Message)
	}
}

func TestMessages_Malformed200_NonJSON_RaisesResponseValidation(t *testing.T) {
	// A 200 with a non-JSON body triggers decodeInto failure → surfaces
	// via the dedicated *ResponseValidationError (NOT *HTTPError, which
	// is reserved for non-2xx transport failures).
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		_, _ = w.Write([]byte("not json at all"))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.Messages(context.Background(), basicMessagesRequest())
	var vErr *ResponseValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("want *ResponseValidationError, got %T (%v)", err, err)
	}
	// rawBodyBytes preserves string inputs verbatim (no JSON re-encoding).
	// Mirrors TestGetCertificate_Malformed200_NonJSON: a non-JSON 2xx body
	// surfaces on .Body as the exact raw bytes the gateway sent. Matches
	// Python's raw-text preservation on the same path.
	if string(vErr.Body) != "not json at all" {
		t.Errorf("Body = %q, want %q (raw, not JSON-quoted)", string(vErr.Body), "not json at all")
	}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		t.Errorf("must not also be *HTTPError")
	}
}

func TestMessages_Malformed202_ProcessingWithWrongType_RaisesResponseValidation(t *testing.T) {
	// Body.status == "processing" takes the async branch; if the body
	// contents are the wrong JSON type for ProxyAcceptedResponse (e.g.
	// job_id as an int instead of a string), decodeInto fails and the
	// dedicated *ResponseValidationError fires.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		// job_id typed as a number — can't unmarshal into string.
		_, _ = w.Write([]byte(`{"status":"processing","job_id":42,"request_id":"r","status_url":"u"}`))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.Messages(context.Background(), basicMessagesRequest())
	var vErr *ResponseValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("want *ResponseValidationError, got %T", err)
	}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		t.Errorf("must not also be *HTTPError")
	}
}

func TestMessages_Sync200_MissingRequiredFields_RaisesResponseValidation(t *testing.T) {
	// json.Unmarshal accepts {"unrelated":"junk"} into ProxySyncResponse
	// with all fields zero. validateProxySyncResponse rejects that so
	// callers don't see a bogus apparent-success with empty Status /
	// ModelUsed.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{"unrelated":"junk"}`))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	resp, err := c.Messages(context.Background(), basicMessagesRequest())
	if resp != nil {
		t.Errorf("expected nil resp on required-field failure")
	}
	var vErr *ResponseValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("want *ResponseValidationError, got %T (%v)", err, err)
	}
	if !strings.Contains(vErr.Message, "ProxySyncResponse") {
		t.Errorf("message should name the type: %q", vErr.Message)
	}
	if !strings.Contains(string(vErr.Body), "unrelated") {
		t.Errorf("Body should contain raw response: %q", string(vErr.Body))
	}
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		t.Errorf("must not also be *HTTPError")
	}
}

func TestMessages_Async202_MissingRequiredFields_RaisesResponseValidation(t *testing.T) {
	// Body.status == "processing" routes to async branch, but all the
	// other required fields (job_id, request_id, status_url) are
	// missing. validateProxyAcceptedResponse rejects.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"processing"}`))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	resp, err := c.Messages(context.Background(), basicMessagesRequest())
	if resp != nil {
		t.Errorf("expected nil resp on required-field failure")
	}
	var vErr *ResponseValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("want *ResponseValidationError, got %T (%v)", err, err)
	}
	if !strings.Contains(vErr.Message, "ProxyAcceptedResponse") {
		t.Errorf("message should name the type: %q", vErr.Message)
	}
	if !strings.Contains(string(vErr.Body), "processing") {
		t.Errorf("Body should preserve raw response: %q", string(vErr.Body))
	}
}

func TestMessages_PlainText2xx_PreservesRawText(t *testing.T) {
	// Regression guard mirroring
	// TestGetCertificate_PlainText2xx_PreservesRawText: a plain-text 2xx
	// body on the Messages path must surface on .Body as exact raw bytes,
	// not JSON-quoted.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "text/plain")
		_, _ = w.Write([]byte("service unavailable"))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.Messages(context.Background(), basicMessagesRequest())
	var vErr *ResponseValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("want *ResponseValidationError, got %T (%v)", err, err)
	}
	if string(vErr.Body) != "service unavailable" {
		t.Errorf("Body = %q, want %q (raw, not JSON-quoted)", string(vErr.Body), "service unavailable")
	}
	if len(vErr.Body) > 0 && vErr.Body[0] == '"' {
		t.Errorf("Body should not be JSON-quoted: %q", string(vErr.Body))
	}
}

func TestMessages_LiteralNullBody_PreservesNullSignal(t *testing.T) {
	// Mirrors TestGetCertificate_LiteralNullBody_PreservesNullSignal: a
	// 2xx with a literal JSON null body parses to Go nil, fails required-
	// field validation, and must surface as *ResponseValidationError with
	// Body = []byte("null") — not nil. Callers can distinguish "gateway
	// sent null" from "SDK forgot to populate .Body" on the Messages
	// path as well as the GetCertificate path.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte("null"))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	resp, err := c.Messages(context.Background(), basicMessagesRequest())
	if resp != nil {
		t.Errorf("expected nil resp on null-body failure")
	}
	var vErr *ResponseValidationError
	if !errors.As(err, &vErr) {
		t.Fatalf("want *ResponseValidationError, got %T (%v)", err, err)
	}
	if string(vErr.Body) != "null" {
		t.Errorf("Body = %q, want %q", string(vErr.Body), "null")
	}
}

func TestMessages_Non2xx_UsesHTTPErrorNotResponseValidation(t *testing.T) {
	// Invariant: non-2xx MUST raise *HTTPError. *ResponseValidationError
	// must never fire for transport-level failure.
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		w.WriteHeader(500)
		_, _ = w.Write([]byte(`{"error": {"code": "upstream_error"}}`))
	}
	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.Messages(context.Background(), basicMessagesRequest())
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want *HTTPError, got %T", err)
	}
	if httpErr.Status != 500 {
		t.Errorf("status = %d", httpErr.Status)
	}
	var vErr *ResponseValidationError
	if errors.As(err, &vErr) {
		t.Errorf("must not also be *ResponseValidationError")
	}
}
