package bundle

import (
	"strings"
	"testing"
)

// The website writer pins the same input and value
// (theveil-website src/app/api/account/conversations/[id]/bundle/__tests__/route.test.ts).
func TestCertificatesDigestGoldenVector(t *testing.T) {
	got := CertificatesDigest(map[string]string{"req-b": strings.Repeat("b", 64), "req-a": strings.Repeat("a", 64)})

	if got != goldenCertificatesDigest {
		t.Fatalf("got %s", got)
	}
}

func TestAllowedPath(t *testing.T) {
	for p, want := range map[string]bool{
		"manifest.json": true, "README.txt": true, "verification.json": true,
		"report-external.pdf": true, "report-internal.pdf": true,
		"certificates/abc123.json": true, "certificates/../manifest.json": false,
		"certificates/a/b.json": false, "audit/events.json": false, "Manifest.json": false,
		"/manifest.json": false, "certificates/..json": false,
	} {
		if AllowedPath(p) != want {
			t.Errorf("%s: want %v", p, want)
		}
	}
}

const goldenCertificatesDigest = "6862bc5d908b18870300fdf3b3b5bc6b03fc0dedc01a8a2a451bca83027fceb7"
