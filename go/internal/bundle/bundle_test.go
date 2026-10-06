package bundle_test

import (
	"strings"
	"testing"

	"github.com/declade/lucairn-sdks/go/internal/bundle"
	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

// TestCorpusInProcess runs every corpus case through bundle.Verify. The same
// corpus runs against the BUILT binary in cmd/lucairn-bundle-verify.
func TestCorpusInProcess(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	// The corpus measures the hosted policy (the binary run passes
	// --require-anchors, see World.CLIFlags).
	roots := co.World.Roots()
	roots.RequireAnchors = true
	for _, c := range co.Cases {
		opt := bundle.Options{Roots: roots}
		for _, fl := range c.Flags {
			if fl == "--online" {
				opt.Fetcher = co.Fetcher()
			}
			if fl == bundletest.FlagAllowUnanchored {
				opt.Roots.RequireAnchors = false
			}
		}
		rep := bundle.Verify(c.Name+".zip", c.Zip, opt)
		switch c.Expect {
		case bundletest.ExpectValid, bundletest.ExpectKnownGap:
			if rep.ExitCode != 0 {
				t.Errorf("%s: want exit 0, got %d %s: %+v", c.Name, rep.ExitCode, rep.Verdict, failing(rep))
			}
		case bundletest.ExpectDetected:
			if rep.ExitCode == 0 {
				t.Errorf("%s: mutation NOT detected (exit 0)", c.Name)
			}
		case bundletest.ExpectTampered:
			if rep.ExitCode != bundle.ExitTampered {
				t.Errorf("%s: want exit 1 (TAMPERED), got %d %s", c.Name, rep.ExitCode, rep.Verdict)
			}
		case bundletest.ExpectIncomplete:
			if rep.ExitCode != bundle.ExitIncomplete {
				t.Errorf("%s: want exit 2 (INCOMPLETE), got %d %s: %+v", c.Name, rep.ExitCode, rep.Verdict, failing(rep))
			}
		default:
			t.Errorf("%s: unknown expectation %q", c.Name, c.Expect)
		}
		if c.Step != "" {
			found := false
			for _, s := range failing(rep) {
				if s.Name == c.Step && strings.Contains(s.Detail, c.Detail) {
					found = true
				}
			}
			if !found {
				t.Errorf("%s: no failing/blocking step %q with detail %q: %+v", c.Name, c.Step, c.Detail, failing(rep))
			}
		}
		t.Logf("%-36s exit %d %-10s %s", c.Name, rep.ExitCode, rep.Verdict, first(rep))
	}
}

func failing(r *bundle.Report) []bundle.Step {
	var out []bundle.Step
	for _, s := range r.Steps {
		if s.Status == bundle.Fail || (s.Status == bundle.Skipped && s.Incomplete) {
			out = append(out, s)
		}
	}
	return out
}

func first(r *bundle.Report) string {
	f := failing(r)
	if len(f) == 0 {
		return ""
	}
	return f[0].Scope + "/" + f[0].Name + ": " + string(f[0].Status) + " " + f[0].Detail
}

// TestProductionRootsDoNotVerifySynthetic: a synthetic bundle checked with
// the built-in pins must never be VALID.
func TestProductionRootsDoNotVerifySynthetic(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	roots, err := bundle.ProductionRoots()
	if err != nil {
		t.Fatal(err)
	}
	rep := bundle.Verify("clean.zip", co.Cases[0].Zip, bundle.Options{Roots: roots})
	if rep.ExitCode == 0 {
		t.Fatal("synthetic bundle verified under production pins")
	}
}
