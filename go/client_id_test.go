package lucairn

import "testing"

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
