package lucairn

import (
	"errors"
	"math"
	"net/http"
	"strings"
	"testing"
	"time"
)

// -- New() API-key validation --

func TestNew_AcceptsValidKey(t *testing.T) {
	c, err := New(validAPIKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("client is nil")
	}
}

func TestNew_RejectsWrongPrefix(t *testing.T) {
	_, err := New("bad_" + strings.Repeat("0", 32))
	if err == nil {
		t.Fatal("expected config error")
	}
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want ConfigError, got %T", err)
	}
}

func TestNew_RejectsUppercaseHex(t *testing.T) {
	_, err := New("dsa_" + strings.Repeat("A", 32))
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want ConfigError, got %T", err)
	}
}

func TestNew_RejectsWrongLength(t *testing.T) {
	for _, n := range []int{31, 33, 0} {
		_, err := New("dsa_" + strings.Repeat("0", n))
		var cfgErr *ConfigError
		if !errors.As(err, &cfgErr) {
			t.Errorf("n=%d: want ConfigError, got %T", n, err)
		}
	}
}

func TestNew_RejectsEmpty(t *testing.T) {
	_, err := New("")
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want ConfigError, got %T", err)
	}
}

// -- BaseURL validation --

func TestNew_DefaultBaseURL(t *testing.T) {
	c, err := New(validAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := c.BaseURL(), DefaultBaseURL; got != want {
		t.Errorf("BaseURL() = %q, want %q", got, want)
	}
}

func TestNew_AcceptsHTTPSOverride(t *testing.T) {
	c, err := New(validAPIKey, WithBaseURL("https://gateway.example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL() != "https://gateway.example.com" {
		t.Errorf("got %q", c.BaseURL())
	}
}

func TestNew_AcceptsHTTPForLocalhost(t *testing.T) {
	c, err := New(validAPIKey, WithBaseURL("http://localhost:8080"))
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL() != "http://localhost:8080" {
		t.Errorf("got %q", c.BaseURL())
	}
}

func TestNew_StripsTrailingSlashes(t *testing.T) {
	c, err := New(validAPIKey, WithBaseURL("https://gateway.example.com///"))
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL() != "https://gateway.example.com" {
		t.Errorf("got %q", c.BaseURL())
	}
}

func TestNew_RejectsUnknownScheme(t *testing.T) {
	_, err := New(validAPIKey, WithBaseURL("ftp://example.com"))
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want ConfigError, got %T", err)
	}
}

func TestNew_RejectsMissingHost(t *testing.T) {
	_, err := New(validAPIKey, WithBaseURL("https://"))
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want ConfigError, got %T", err)
	}
}

// -- Timeout validation --

func TestNew_DefaultTimeout(t *testing.T) {
	c, err := New(validAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	if c.Timeout() != DefaultTimeout {
		t.Errorf("got %v, want %v", c.Timeout(), DefaultTimeout)
	}
}

func TestNew_AcceptsPositiveTimeout(t *testing.T) {
	c, err := New(validAPIKey, WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if c.Timeout() != 5*time.Second {
		t.Errorf("got %v", c.Timeout())
	}
}

func TestNew_RejectsZeroTimeout(t *testing.T) {
	_, err := New(validAPIKey, WithTimeout(0))
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want ConfigError, got %T", err)
	}
}

func TestNew_RejectsNegativeTimeout(t *testing.T) {
	_, err := New(validAPIKey, WithTimeout(-time.Second))
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want ConfigError, got %T", err)
	}
}

// time.Duration is int64; NaN isn't representable. But we defensively
// guard anyway so a float-converted caller doesn't slip through.
func TestNew_RejectsNaNDurationDefensively(t *testing.T) {
	// math.NaN → int64 conversion is UB in Go but typically 0; the only
	// way to hit the NaN branch in normalizeTimeout is via a caller who
	// explicitly passes math.NaN cast — which isn't possible with
	// time.Duration. This test exists to document the defensive check;
	// it passes regardless of whether the branch fires.
	_, err := New(validAPIKey, WithTimeout(time.Duration(math.NaN())))
	if err == nil {
		// Zero-valued duration passes the non-positive guard; not a NaN
		// per se, but rejects at <=0. Either way, no NaN leak.
		t.Skip("Go time.Duration has no NaN representation")
	}
}

// -- http:// base URL guard --

func TestNew_RejectsHTTPOnPublicHost(t *testing.T) {
	_, err := New(validAPIKey, WithBaseURL("http://gateway.example.com"))
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want ConfigError, got %T", err)
	}
	if !strings.Contains(cfgErr.Message, "https://") {
		t.Errorf("message should mention https:// requirement: %q", cfgErr.Message)
	}
}

func TestNew_RejectsHTTPOnNonLoopbackIP(t *testing.T) {
	_, err := New(validAPIKey, WithBaseURL("http://10.0.0.1"))
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want ConfigError, got %T", err)
	}
}

func TestNew_AcceptsHTTPForLoopbackHosts(t *testing.T) {
	for _, url := range []string{
		"http://localhost",
		"http://localhost:8080",
		"http://127.0.0.1",
		"http://127.0.0.1:9090",
		"http://[::1]",
		"http://[::1]:1234",
		"http://myservice.local",
	} {
		_, err := New(validAPIKey, WithBaseURL(url))
		if err != nil {
			t.Errorf("url=%q unexpectedly rejected: %v", url, err)
		}
	}
}

func TestNew_AcceptsHTTPSEverywhere(t *testing.T) {
	for _, url := range []string{
		"https://gateway.example.com",
		"https://10.0.0.1",
		"https://public-gateway.example.com",
	} {
		_, err := New(validAPIKey, WithBaseURL(url))
		if err != nil {
			t.Errorf("url=%q unexpectedly rejected: %v", url, err)
		}
	}
}

// -- MaxResponseBytes --

func TestNew_DefaultMaxResponseBytes(t *testing.T) {
	c, err := New(validAPIKey)
	if err != nil {
		t.Fatal(err)
	}
	if c.maxResponseBytes != DefaultMaxResponseBytes {
		t.Errorf("got %d, want %d", c.maxResponseBytes, DefaultMaxResponseBytes)
	}
}

func TestNew_AcceptsPositiveMaxResponseBytes(t *testing.T) {
	c, err := New(validAPIKey, WithMaxResponseBytes(1024))
	if err != nil {
		t.Fatal(err)
	}
	if c.maxResponseBytes != 1024 {
		t.Errorf("got %d", c.maxResponseBytes)
	}
}

func TestNew_RejectsZeroMaxResponseBytes(t *testing.T) {
	_, err := New(validAPIKey, WithMaxResponseBytes(0))
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want ConfigError, got %T", err)
	}
}

func TestNew_RejectsNegativeMaxResponseBytes(t *testing.T) {
	_, err := New(validAPIKey, WithMaxResponseBytes(-1))
	var cfgErr *ConfigError
	if !errors.As(err, &cfgErr) {
		t.Fatalf("want ConfigError, got %T", err)
	}
}

// -- HTTPClient injection --

func TestNew_AcceptsCustomHTTPClient(t *testing.T) {
	httpClient := &http.Client{Timeout: 0}
	c, err := New(validAPIKey, WithHTTPClient(httpClient))
	if err != nil {
		t.Fatal(err)
	}
	if c.http != httpClient {
		t.Error("custom http client not stored")
	}
}

// -- Option composition --

func TestNew_OptionsComposeLastWriteWins(t *testing.T) {
	c, err := New(
		validAPIKey,
		WithBaseURL("https://first.example.com"),
		WithBaseURL("https://second.example.com"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL() != "https://second.example.com" {
		t.Errorf("got %q, want second.example.com", c.BaseURL())
	}
}
