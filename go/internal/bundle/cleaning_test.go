package bundle_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/declade/lucairn-sdks/go/internal/bundle"
	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

func TestCleaningScopeInBothReports(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		k, n int
	}{
		{"Cleaning-00-three", 3, 3},
		{"Cleaning-00-three-online", 3, 3},
		{"Cleaning-07-mixed", 1, 3},
		{"S2b-00-clean-v2", 0, 4},
		{"Cleaning-01-middle-removed", 0, 2},
		{"Cleaning-04-downgrade", 0, 0},
		{"Cleaning-05-zero-events", 0, 0},
		{"Cleaning-06-no-root-allow-unanchored", 0, 3},
		{"Cleaning-12-extra-claim", 0, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var data []byte
			opt := bundle.Options{Roots: co.World.Roots()}
			opt.Roots.RequireAnchors = true
			for _, c := range co.Cases {
				if c.Name == tc.name {
					data = c.Zip
					for _, flag := range c.Flags {
						if flag == "--online" {
							opt.Fetcher = co.Fetcher()
						}
						if flag == bundletest.FlagAllowUnanchored {
							opt.Roots.RequireAnchors = false
						}
					}
				}
			}
			if data == nil {
				t.Fatal("missing corpus case")
			}
			r := bundle.Verify(tc.name, data, opt)
			if r.CleaningSteps != tc.k || r.AuditEvents != tc.n {
				t.Fatalf("counts: %d of %d, want %d of %d", r.CleaningSteps, r.AuditEvents, tc.k, tc.n)
			}
			var js strings.Builder
			if err := r.WriteJSON(&js); err != nil {
				t.Fatal(err)
			}
			var decoded map[string]any
			if err := json.Unmarshal([]byte(js.String()), &decoded); err != nil {
				t.Fatal(err)
			}
			out := text(r)
			if tc.k == 0 {
				if r.CleaningScope != "" || decoded["cleaning_scope"] != nil || strings.Contains(out, "entries in this bundle are cleaning steps.") {
					t.Fatal("unaccepted steps produced a scope statement")
				}
			} else {
				want := fmt.Sprintf("%d of the %d entries in this bundle are cleaning steps. For these, this bundle covers the step in which Lucairn cleaned your text; the model call went from your computer directly to the vendor and is not part of this record.", tc.k, tc.n)
				if r.CleaningScope != want || decoded["cleaning_scope"] != want || decoded["cleaning_steps"] != float64(tc.k) || strings.Count(out, want) != 1 || strings.Count(js.String(), want) != 1 {
					t.Fatalf("scope not printed exactly once in each mode: %s\n%s", out, js.String())
				}
				if !strings.Contains(out, bundle.CleaningStepLimitReason) || !strings.Contains(js.String(), bundle.CleaningStepLimitReason) {
					t.Fatal("missing linkage and pre-record loss limits")
				}
			}
			for _, b := range []byte(out) {
				if b > 127 {
					t.Fatal("non-ASCII human report")
				}
			}
			for _, forbidden := range []string{"no request is missing", "proves the conversation is complete", "tamper-proof", "certified"} {
				if strings.Contains(out, forbidden) || strings.Contains(js.String(), forbidden) {
					t.Fatalf("forbidden output phrase %q", forbidden)
				}
			}
		})
	}
}

func TestCleaningRequiresVerifiedKeysAndProofs(t *testing.T) {
	w, err := bundletest.NewWorld("cleaning-trust")
	if err != nil {
		t.Fatal(err)
	}
	sc, err := w.NewCleaningScenario(false, bundletest.CleaningOptions{})
	if err != nil {
		t.Fatal(err)
	}
	// Scope belongs to accepted entries even when exporter completeness
	// blocks the overall result for an unrelated reason.
	partial := sc.Clean.Clone()
	m := partial.Manifest()
	m.Completeness.Listing = "partial"
	partial.WriteManifest(m)
	r := bundle.Verify("partial-listing.zip", partial.Zip(), bundle.Options{Roots: w.Roots()})
	if r.ExitCode != bundle.ExitIncomplete || r.CleaningSteps != 3 || r.CleaningScope == "" {
		t.Fatalf("partial listing lost its accepted cleaning scope: %s", text(r))
	}
	for _, key := range []string{"dsa-gateway", "dsa-sanitizer", "dsa-audit"} {
		t.Run(key, func(t *testing.T) {
			roots := w.Roots()
			delete(roots.ServiceKeys, key)
			r := bundle.Verify("missing-key.zip", sc.Clean.Zip(), bundle.Options{Roots: roots})
			if r.ExitCode == 0 || r.CleaningSteps != 0 {
				t.Fatalf("unverified cleaning accepted: %s", text(r))
			}
		})
	}
	f := sc.Clean.Clone()
	f.PutList(bundle.PathAuditProofs, []any{})
	f.Rehash()
	r = bundle.Verify("missing-proof.zip", f.Zip(), bundle.Options{Roots: w.Roots()})
	if r.ExitCode != bundle.ExitTampered || r.CleaningSteps != 0 {
		t.Fatalf("missing proofs accepted: %s", text(r))
	}
}
