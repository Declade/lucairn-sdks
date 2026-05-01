package lucairn

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// GetCertificateSummary returns the gateway's text/html summary as a
// raw string. Per the gateway: the assembled state returns HTTP 200 via
// renderSummaryHTML (veil.go:807); the pending state returns HTTP 202
// via renderPendingSummaryHTML (veil.go:848). The SDK propagates 202 as
// a typed *HTTPError so callers can distinguish pending from assembled.

func TestGetCertificateSummary_HappyPath(t *testing.T) {
	const summaryHTML = `<!DOCTYPE html><html><body><h1>Veil Certificate</h1><p>req_test_001</p></body></html>`

	handler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", r.Method)
		}
		if r.URL.Path != "/api/v1/veil/certificate/req_test_001/summary" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if r.Header.Get("x-api-key") != validAPIKey {
			t.Errorf("x-api-key missing or wrong")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(summaryHTML))
	}

	c, server := newMockedClient(t, handler)
	defer server.Close()

	got, err := c.GetCertificateSummary(context.Background(), "req_test_001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != summaryHTML {
		t.Errorf("html = %q, want %q", got, summaryHTML)
	}
}

func TestGetCertificateSummary_PendingReturnsHTMLAt202(t *testing.T) {
	// Gateway returns HTTP 202 for the pending state via
	// renderPendingSummaryHTML (dual-sandbox-architecture/services/
	// gateway/internal/api/veil.go:848). The SDK surfaces this as a
	// typed *HTTPError with Status=202 and Body holding the pending
	// HTML — same precedent as GetCertificate at lucairn.go:194-201.
	// This test locks the body-preservation contract: the pending HTML
	// must be on the error's Body field so callers can render it
	// without re-fetching.
	const pendingHTML = `<!DOCTYPE html><html><body><div class="pending">PENDING</div></body></html>`

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(pendingHTML))
	}

	c, server := newMockedClient(t, handler)
	defer server.Close()

	got, err := c.GetCertificateSummary(context.Background(), "req_pending")
	if got != "" {
		t.Errorf("html should be empty on 202 path, got %q", got)
	}
	if err == nil {
		t.Fatalf("expected error on 202 path, got nil")
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want *HTTPError, got %T (%v)", err, err)
	}
	body, ok := httpErr.Body.(string)
	if !ok {
		t.Fatalf("body type = %T, want string (raw HTML)", httpErr.Body)
	}
	if !strings.Contains(body, "PENDING") {
		t.Errorf("body should contain PENDING marker, got %q", body)
	}
}

func TestGetCertificateSummary_PendingRaises202HTTPError(t *testing.T) {
	// Companion to TestGetCertificateSummary_PendingReturnsHTMLAt202 —
	// this test specifically locks the typed-error contract: callers
	// branching on errors.As(err, &httpErr) && httpErr.Status == 202
	// MUST get a typed *HTTPError back with Status=202. Mirrors the
	// pattern in TestGetCertificate_PendingRaisesHTTPErrorWith202 at
	// get_certificate_test.go:64-97.
	const pendingHTML = `<!doctype html>... pending banner ...`

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(pendingHTML))
	}

	c, server := newMockedClient(t, handler)
	defer server.Close()

	summary, err := c.GetCertificateSummary(context.Background(), "req_pending")
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want *HTTPError, got %T (%v)", err, err)
	}
	if httpErr.Status != 202 {
		t.Errorf("status = %d, want 202", httpErr.Status)
	}
	if summary != "" {
		t.Errorf("summary = %q, want empty string on 202 path", summary)
	}
}

func TestGetCertificateSummary_503Unavailable(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"code":"veil_unavailable","message":"Veil Witness is temporarily unavailable."}`))
	}

	c, server := newMockedClient(t, handler)
	defer server.Close()

	_, err := c.GetCertificateSummary(context.Background(), "req_x")
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		t.Fatalf("want *HTTPError, got %T (%v)", err, err)
	}
	if httpErr.Status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", httpErr.Status)
	}
}

func TestGetCertificateSummary_RequestIDPathEscape(t *testing.T) {
	// Path-escape: the raw request id contains a slash, which url.PathEscape
	// percent-encodes; the SDK emits the encoded form on the wire and the
	// gateway tolerates it. Servers (Go's net/http included) decode the
	// path before exposing r.URL.Path, so we inspect r.URL.RawPath which
	// preserves the on-wire encoded form when it differs from the decoded
	// form. Same encoding pattern as GetCertificate at lucairn.go:186-187.
	const id = "req/with/slashes"
	var seenRawPath, seenPath string

	handler := func(w http.ResponseWriter, r *http.Request) {
		seenRawPath = r.URL.RawPath
		seenPath = r.URL.Path
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}

	c, server := newMockedClient(t, handler)
	defer server.Close()

	if _, err := c.GetCertificateSummary(context.Background(), id); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasSuffix(seenPath, "/summary") {
		t.Errorf("decoded path %q does not end in /summary", seenPath)
	}
	if !strings.Contains(seenRawPath, "req%2Fwith%2Fslashes") {
		t.Errorf("raw path %q missing percent-encoded slashes (decoded was %q)", seenRawPath, seenPath)
	}
}

func TestGetCertificateSummary_EmptyRequestID(t *testing.T) {
	c, err := New(validAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.GetCertificateSummary(context.Background(), "")
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want *ConfigError, got %T (%v)", err, err)
	}
}
