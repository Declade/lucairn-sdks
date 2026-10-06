package bundle_test

import (
	"testing"

	"github.com/declade/lucairn-sdks/go/internal/bundle"
	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

// TestCorpusInProcess runs every corpus case through bundle.Verify. The same
// corpus runs against the BUILT binary in cmd/lucairn-verify.
func TestCorpusInProcess(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	opt := bundle.Options{Roots: co.World.Roots()}
	for _, c := range co.Cases {
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
