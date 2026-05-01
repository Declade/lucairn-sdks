package lucairn

import (
	"context"
	"net/http"
	"testing"
)

// W2A-B1: ClientID is *string so the protojson shape (nil -> null;
// populated -> quoted string) round-trips through the SDK without
// flattening the absent / present distinction. GetClientID is the
// convenience accessor that returns "" for both nil-receiver and
// nil-field — see types.go for the rationale on keeping ClientID a
// pointer.

func TestGetClientID_NilReceiver(t *testing.T) {
	var c *VeilCertificate
	if got := c.GetClientID(); got != "" {
		t.Errorf("nil receiver: got %q, want empty", got)
	}
}

func TestGetClientID_NilField(t *testing.T) {
	c := &VeilCertificate{}
	if got := c.GetClientID(); got != "" {
		t.Errorf("nil field: got %q, want empty", got)
	}
}

func TestGetClientID_Populated(t *testing.T) {
	id := "org_test_abc"
	c := &VeilCertificate{ClientID: &id}
	if got := c.GetClientID(); got != "org_test_abc" {
		t.Errorf("populated: got %q, want org_test_abc", got)
	}
}

func TestGetClientID_PopulatedEmpty(t *testing.T) {
	// Distinguishable from nil at the pointer level even though
	// GetClientID() collapses both to "". Lock that the field-direct
	// inspection still works.
	empty := ""
	c := &VeilCertificate{ClientID: &empty}
	if c.ClientID == nil {
		t.Errorf("ClientID pointer should be non-nil")
	}
	if got := c.GetClientID(); got != "" {
		t.Errorf("populated-empty: got %q, want empty", got)
	}
}

// TestGetCertificate_ClientIDUnmarshalsCorrectly locks the JSON
// unmarshal contract for the ClientID *string field on the full
// GetCertificate transport path (decodeInto round-trip via
// json.Marshal+Unmarshal at lucairn.go:639-645). The previous
// client_id_test.go cases exercise the nil-receiver and direct-field
// accessors only; this regression closes the gap by routing through
// the actual SDK request path so a future change to the json tag,
// pointer-vs-value field type, or decode helper would fail loudly.
//
// Three table-driven cases:
//   - client_id present: cert.ClientID points to "org_x".
//   - client_id null: cert.ClientID is nil (json.Unmarshal handles
//     `null` by zeroing the pointer).
//   - client_id absent: cert.ClientID is nil (omitempty + missing).
func TestGetCertificate_ClientIDUnmarshalsCorrectly(t *testing.T) {
	// Minimum cert shape that satisfies validateVeilCertificate at
	// lucairn.go:363-380 (certificate_id + request_id +
	// witness_signature + witness_key_id + issued_at). Build the JSON
	// body inline so each case can vary the client_id key/value
	// independently.
	const baseFields = `"certificate_id":"veil_test_unmarshal_001",` +
		`"request_id":"req_test_unmarshal_001",` +
		`"witness_signature":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",` +
		`"witness_key_id":"witness_v1",` +
		`"issued_at":"2026-05-01T12:00:00Z"`

	cases := []struct {
		name        string
		bodyJSON    string
		wantNonNil  bool
		wantPointee string
	}{
		{
			name:        "ClientIDPresent",
			bodyJSON:    `{` + baseFields + `,"client_id":"org_x"}`,
			wantNonNil:  true,
			wantPointee: "org_x",
		},
		{
			name:        "ClientIDNull",
			bodyJSON:    `{` + baseFields + `,"client_id":null}`,
			wantNonNil:  false,
			wantPointee: "",
		},
		{
			name:        "ClientIDAbsent",
			bodyJSON:    `{` + baseFields + `}`,
			wantNonNil:  false,
			wantPointee: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := tc.bodyJSON
			handler := func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("content-type", "application/json")
				_, _ = w.Write([]byte(body))
			}
			c, server := newMockedClient(t, handler)
			defer server.Close()

			cert, err := c.GetCertificate(context.Background(), "req_test_unmarshal_001")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cert == nil {
				t.Fatalf("cert is nil")
			}
			if tc.wantNonNil {
				if cert.ClientID == nil {
					t.Fatalf("ClientID is nil, want non-nil pointing to %q", tc.wantPointee)
				}
				if *cert.ClientID != tc.wantPointee {
					t.Errorf("*ClientID = %q, want %q", *cert.ClientID, tc.wantPointee)
				}
				if got := cert.GetClientID(); got != tc.wantPointee {
					t.Errorf("GetClientID() = %q, want %q", got, tc.wantPointee)
				}
			} else {
				if cert.ClientID != nil {
					t.Errorf("ClientID should be nil, got pointer to %q", *cert.ClientID)
				}
				if got := cert.GetClientID(); got != "" {
					t.Errorf("GetClientID() = %q, want empty for nil ClientID", got)
				}
			}
		})
	}
}
