package lucairn

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// GetCertificateSummary returns the gateway's text/html summary as a
// raw string. The gateway emits HTTP 200 for both pending and assembled
// states (see veil.go:391-407 — pending falls through to
// renderPendingSummaryHTML which writes status=200 + Content-Type:
// text/html), so the SDK does NOT distinguish; callers can pattern-
// match the HTML or chain GetCertificate.

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

func TestGetCertificateSummary_PendingReturnsHTMLAt200(t *testing.T) {
	const pendingHTML = `<!DOCTYPE html><html><body><div class="pending">PENDING</div></body></html>`

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(pendingHTML))
	}

	c, server := newMockedClient(t, handler)
	defer server.Close()

	got, err := c.GetCertificateSummary(context.Background(), "req_pending")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "PENDING") {
		t.Errorf("expected PENDING marker, got %q", got)
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
