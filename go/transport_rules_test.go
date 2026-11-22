package lucairn

// Transport rules for key-carrying requests (security fix stream T-1474,
// slice F16; level-2 entry 11 and low 12):
//   - the client never follows a redirect, so the API key is never sent to
//     the address a Location header names (also with a caller-supplied
//     *http.Client, which is copied, never mutated);
//   - plain http:// base addresses are refused except for this machine.
// Synthetic key, two local stand-in servers only.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestClient_NeverFollowsRedirect_KeyNotSentToSecondAddress(t *testing.T) {
	var secondHits atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		w.Header().Set("content-type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer second.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL+"/v1/x", http.StatusTemporaryRedirect)
	}))
	defer first.Close()

	callerClient := &http.Client{} // follows redirects by default
	for name, opts := range map[string][]Option{
		"default client":         {WithBaseURL(first.URL)},
		"caller-supplied client": {WithBaseURL(first.URL), WithHTTPClient(callerClient)},
	} {
		t.Run(name, func(t *testing.T) {
			secondHits.Store(0)
			c, err := New(validAPIKey, opts...)
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.GetCertificate(context.Background(), "req_f16_redirect")
			var httpErr *HTTPError
			if !errors.As(err, &httpErr) || httpErr.Status != http.StatusTemporaryRedirect {
				t.Fatalf("want *HTTPError 307, got %T %v", err, err)
			}
			if n := secondHits.Load(); n != 0 {
				t.Fatalf("second address received %d request(s)", n)
			}
		})
	}
	if callerClient.CheckRedirect != nil {
		t.Fatal("caller-supplied *http.Client was mutated")
	}
}

func TestNew_PlainHTTPRefusedOffThisMachine(t *testing.T) {
	for _, u := range []string{
		"http://gateway.example.com",
		"HTTP://gateway.example.com",
		"http://localhost.evil.example",
		"http://localhost@evil.example",
		"http://127.0.0.1@evil.example",
		"http://127.0.0.1.evil.example",
		"http://evil.example#@localhost",
		"http://128.0.0.1",
		"http://myservice.local",
		"http://[::ffff:127.0.0.1]",
	} {
		_, err := New(validAPIKey, WithBaseURL(u))
		var cfgErr *ConfigError
		if !errors.As(err, &cfgErr) {
			t.Errorf("url=%q: want ConfigError, got %v", u, err)
		}
	}
}
