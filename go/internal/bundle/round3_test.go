package bundle_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/bundle"
	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

// T-1231 S2a round 3 (gate "Round-2 verdict", items S1-S6). Synthetic data only.

func corpusCase(t *testing.T, co *bundletest.Corpus, name string) bundletest.Case {
	t.Helper()
	for _, c := range co.Cases {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("corpus lacks %s", name)
	return bundletest.Case{}
}

// S1 (Sol #77 P1): a post-cutover certificate whose marker is relabelled
// legacy (or whose whole attestation is gone) and whose anchors and
// anchor_status are removed is TAMPERED under the hosted policy AND under
// --allow-unanchored. The finding sits on the anchor steps, not on a
// "not anchored" skip.
func TestS1_MarkerRuleHoldsWithoutAnchors(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"S2a-14-solp1-77-legacy-marker-no-anchors", "S2a-16-attestation-removed"} {
		c := corpusCase(t, co, name)
		for _, pol := range []struct {
			name    string
			require bool
		}{{"hosted (anchors required)", true}, {"--allow-unanchored", false}} {
			roots := co.World.Roots()
			roots.RequireAnchors = pol.require
			rep := bundle.Verify(name+".zip", c.Zip, bundle.Options{Roots: roots})
			var buf strings.Builder
			rep.WriteText(&buf)
			if rep.ExitCode != bundle.ExitTampered {
				t.Fatalf("%s / %s: exit %d, want 1\n%s", name, pol.name, rep.ExitCode, buf.String())
			}
			fails := 0
			for _, s := range rep.Steps {
				if (s.Name == "timestamp" || s.Name == "rekor") && s.Status == bundle.Fail && strings.Contains(s.Detail, "does not declare binding v1") {
					fails++
				}
			}
			if fails != 2 {
				t.Fatalf("%s / %s: want both anchor steps FAIL on the missing marker, got %d\n%s", name, pol.name, fails, buf.String())
			}
		}
	}
	// The allow-unanchored variants exist in the corpus with the flag set.
	for _, name := range []string{"S2a-14-solp1-77-legacy-marker-no-anchors-allow-unanchored", "S2a-16-attestation-removed-allow-unanchored"} {
		c := corpusCase(t, co, name)
		if c.Expect != bundletest.ExpectTampered || len(c.Flags) != 1 || c.Flags[0] != bundletest.FlagAllowUnanchored {
			t.Fatalf("%s: expect %s flags %v", name, c.Expect, c.Flags)
		}
	}
}

// The honest counterpart: a binding-v1 certificate issued after the cutover
// whose rails both failed keeps cert_hash + the marker (the witness writes
// them, X1). It is INCOMPLETE under the hosted policy and VALID under
// --allow-unanchored — never TAMPERED.
func TestS1_HonestBothRailsFailedCertificate(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	// Strip the anchors but keep cert_hash + marker: what the witness records
	// when both rails fail.
	ro := co.RekorOnly
	var doc map[string]any
	raw, _ := json.Marshal(ro.Doc)
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	att := doc["attestation"].(map[string]any)
	delete(att, "transparency_log")
	doc["anchor_status"] = map[string]any{"status": "ANCHOR_STATUS_FAILED", "attempts": 3}
	honest := *ro
	honest.Doc = doc
	if err := honest.Remarshal(); err != nil {
		t.Fatal(err)
	}
	b := bundletest.Build(bundletest.Spec{ConversationID: bundletest.ConvA, CustomerID: bundletest.Customer, Certs: []*bundletest.Cert{&honest}})
	roots := co.World.Roots()
	for _, tc := range []struct {
		name    string
		require bool
		exit    int
	}{{"hosted", true, bundle.ExitIncomplete}, {"--allow-unanchored", false, bundle.ExitValid}} {
		roots.RequireAnchors = tc.require
		rep := bundle.Verify("honest.zip", b.Zip(), bundle.Options{Roots: roots})
		if rep.ExitCode != tc.exit {
			var buf strings.Builder
			rep.WriteText(&buf)
			t.Fatalf("%s: exit %d, want %d\n%s", tc.name, rep.ExitCode, tc.exit, buf.String())
		}
	}
}

// S3: the "checked content-bound" line is printed only when a content-bound
// comparison actually passed on this run.
func TestS3_ContentBoundSummaryIsConditional(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		bound bool
	}{{"00-clean", false}, {"S2a-00-clean-bound", true}} {
		c := corpusCase(t, co, tc.name)
		rep := bundle.Verify(tc.name+".zip", c.Zip, bundle.Options{Roots: co.World.Roots()})
		var buf strings.Builder
		rep.WriteText(&buf)
		out := buf.String()
		if got := strings.Contains(out, "CONTENT-BOUND:"); got != tc.bound || (rep.ContentBound > 0) != tc.bound {
			t.Fatalf("%s: CONTENT-BOUND line present=%v count=%d, want %v\n%s", tc.name, got, rep.ContentBound, tc.bound, out)
		}
		if strings.Contains(out, "Certificates with binding v1 are checked content-bound") {
			t.Fatalf("%s: the unconditional content-bound sentence is still printed", tc.name)
		}
	}
}

// S4 (ToB #77 I2): if the signed issued_at cannot be recovered after the
// signature verified, a configured cutover must not switch off silently: a
// blocking SKIPPED step, so the result is never VALID.
func TestS4_SignedBytesRecoveryFailureBlocks(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	c := corpusCase(t, co, "S2a-00-clean-bound")
	restore := bundle.SetSignedBytesOfForTest(true)
	defer restore()
	rep := bundle.Verify("c.zip", c.Zip, bundle.Options{Roots: co.World.Roots()})
	if rep.ExitCode == bundle.ExitValid {
		t.Fatal("recovery failure with a cutover set produced VALID")
	}
	found := false
	for _, s := range rep.Steps {
		if s.Name == "anchor-binding" && s.Status == bundle.Skipped && s.Incomplete {
			found = true
		}
	}
	if !found {
		t.Fatal("no blocking SKIPPED anchor-binding step")
	}
	// Without a cutover the step is not added (nothing to apply).
	roots := co.World.Roots()
	roots.BindingRequiredAfter = time.Time{}
	rep = bundle.Verify("c.zip", c.Zip, bundle.Options{Roots: roots})
	for _, s := range rep.Steps {
		if s.Name == "anchor-binding" {
			t.Fatalf("anchor-binding step without a cutover: %+v", s)
		}
	}
}

// S5: the legacy-marker parse equals the witness's anchorbinding.FormOf
// (dual-sandbox-architecture services/veil-witness/internal/anchorbinding/
// binding.go): "lucairn.anchor-binding/v1" → v1; "SHA-256" and "" → legacy;
// anything else → unknown. Absent / JSON null = "" (protojson omits an empty
// string), a non-string → unknown.
func TestS5_FormParityWithWitnessFormOf(t *testing.T) {
	for in, want := range map[any]string{
		"lucairn.anchor-binding/v1":  "v1",
		"SHA-256":                    "legacy",
		"":                           "legacy",
		"sha256":                     "unknown",
		"SHA256":                     "unknown",
		"sha-256":                    "unknown",
		" SHA-256":                   "unknown",
		"lucairn.anchor-binding/v2":  "unknown",
		"LUCAIRN.ANCHOR-BINDING/V1":  "unknown",
		"lucairn.anchor-binding/v1 ": "unknown",
		float64(1):                   "unknown",
	} {
		if got := bundle.FormNameForTest(in); got != want {
			t.Errorf("hash_algorithm %#v: %s, want %s", in, got, want)
		}
	}
	if got := bundle.FormNameForTest(nil); got != "legacy" {
		t.Errorf("null: %s, want legacy", got)
	}
}

// S6: the unknown-marker message quotes the value exactly as recorded (no
// trimming inside the quotes) and marks shortening outside them.
func TestS6_UnknownMarkerMessageQuotesExactValue(t *testing.T) {
	if got := bundle.QuotedShortForTest(" lucairn.anchor-binding/v1 "); got != `" lucairn.anchor-binding/v1 "` {
		t.Fatalf("got %s", got)
	}
	long := strings.Repeat("x", 500)
	got := bundle.QuotedShortForTest(long)
	if !strings.HasPrefix(got, `"`+strings.Repeat("x", 120)+`" (first 120 of 500 bytes)`) {
		t.Fatalf("got %s", got)
	}
}
