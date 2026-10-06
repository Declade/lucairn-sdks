package bundle_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/bundle"
	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

func stepOf(r *bundle.Report, scope, name string) *bundle.Step {
	for i := range r.Steps {
		if r.Steps[i].Name == name && (scope == "" || r.Steps[i].Scope == scope) {
			return &r.Steps[i]
		}
	}
	return nil
}

// An unanchored (self-hosted, no TSA/Rekor) certificate is SKIPPED(not
// anchored) — never PASS, never FAIL — and does not block VALID.
func TestUnanchoredBundleIsValidWithSkippedAnchors(t *testing.T) {
	w, err := bundletest.NewWorld("unanchored")
	if err != nil {
		t.Fatal(err)
	}
	c, err := w.NewCert(bundletest.CertOptions{ConversationID: "conv-u", CustomerID: "cust-u", IssuedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), NoAnchors: true})
	if err != nil {
		t.Fatal(err)
	}
	f := bundletest.Build(bundletest.Spec{ConversationID: "conv-u", CustomerID: "cust-u", Certs: []*bundletest.Cert{c}})
	rep := bundle.Verify("u.zip", f.Zip(), bundle.Options{Roots: w.Roots()})
	if rep.ExitCode != 0 {
		t.Fatalf("exit %d: %+v", rep.ExitCode, rep.Steps)
	}
	for _, n := range []string{"timestamp", "rekor"} {
		s := stepOf(rep, c.RequestID, n)
		if s == nil || s.Status != bundle.Skipped || s.Incomplete {
			t.Fatalf("%s: %+v", n, s)
		}
	}
}

// Without service keys (a different witness given, no --service-key) the
// claim and binding steps cannot run: INCOMPLETE, not VALID.
func TestNoServiceKeysIsIncomplete(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	roots := co.World.Roots()
	roots.ServiceKeys = nil
	rep := bundle.Verify("c.zip", co.Cases[0].Zip, bundle.Options{Roots: roots})
	if rep.ExitCode != 2 {
		t.Fatalf("exit %d", rep.ExitCode)
	}
}

type stubFetcher map[int64]*bundle.FetchedEntry

func (s stubFetcher) Fetch(i int64) (*bundle.FetchedEntry, error) {
	if e, ok := s[i]; ok {
		return e, nil
	}
	return nil, fmt.Errorf("no entry %d", i)
}

func entryOf(t *testing.T, c *bundletest.Cert) *bundle.FetchedEntry {
	t.Helper()
	tl := c.Doc["attestation"].(map[string]any)["transparency_log"].(map[string]any)
	dec := func(k string) []byte {
		b, err := base64.StdEncoding.DecodeString(tl[k].(string))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	idx, _ := strconv.ParseInt(tl["log_index"].(string), 10, 64)
	it, _ := strconv.ParseInt(tl["integrated_time"].(string), 10, 64)
	return &bundle.FetchedEntry{Body: dec("canonical_body"), IntegratedTime: it, LogIndex: idx,
		SignedEntryTimestamp: dec("signed_entry_timestamp"), InclusionProof: dec("inclusion_proof")}
}

// --online: a stored entry that agrees with the log passes; a legacy entry
// (no stored body) is SKIPPED offline and PASSES online; a log that serves a
// different body fails.
func TestOnlineRefetch(t *testing.T) {
	w, err := bundletest.NewWorld("online")
	if err != nil {
		t.Fatal(err)
	}
	c, err := w.NewCert(bundletest.CertOptions{ConversationID: "conv-o", CustomerID: "cust-o", IssuedAt: time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	e := entryOf(t, c)
	legacy := *c
	legacy.Doc = map[string]any{}
	raw, _ := json.Marshal(c.Doc)
	_ = json.Unmarshal(raw, &legacy.Doc)
	tl := legacy.Doc["attestation"].(map[string]any)["transparency_log"].(map[string]any)
	delete(tl, "canonical_body")
	delete(tl, "integrated_time")
	if err := legacy.Remarshal(); err != nil {
		t.Fatal(err)
	}
	zipOf := func(x *bundletest.Cert) []byte {
		return bundletest.Build(bundletest.Spec{ConversationID: "conv-o", CustomerID: "cust-o", Certs: []*bundletest.Cert{x}}).Zip()
	}

	off := bundle.Verify("l.zip", zipOf(&legacy), bundle.Options{Roots: w.Roots()})
	if s := stepOf(off, c.RequestID, "rekor"); off.ExitCode != 2 || s == nil || s.Status != bundle.Skipped || !s.Incomplete {
		t.Fatalf("legacy offline: exit %d %+v", off.ExitCode, s)
	}
	on := bundle.Verify("l.zip", zipOf(&legacy), bundle.Options{Roots: w.Roots(), Fetcher: stubFetcher{e.LogIndex: e}})
	if on.ExitCode != 0 {
		t.Fatalf("legacy online: exit %d %+v", on.ExitCode, on.Steps)
	}
	bad := *e
	bad.Body = append(append([]byte(nil), e.Body...), ' ')
	rep := bundle.Verify("c.zip", zipOf(c), bundle.Options{Roots: w.Roots(), Fetcher: stubFetcher{e.LogIndex: &bad}})
	if rep.ExitCode != 1 {
		t.Fatalf("diverging log: exit %d", rep.ExitCode)
	}

	// The HTTP fetcher parses a Rekor v1 envelope.
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/log/entries" || r.URL.Query().Get("logIndex") != strconv.FormatInt(e.LogIndex, 10) {
			http.NotFound(rw, r)
			return
		}
		_ = json.NewEncoder(rw).Encode(map[string]any{"uuid1": map[string]any{
			"body": base64.StdEncoding.EncodeToString(e.Body), "integratedTime": e.IntegratedTime, "logIndex": e.LogIndex,
			"verification": map[string]any{"inclusionProof": json.RawMessage(e.InclusionProof), "signedEntryTimestamp": base64.StdEncoding.EncodeToString(e.SignedEntryTimestamp)},
		}})
	}))
	defer srv.Close()
	viaHTTP := bundle.Verify("c.zip", zipOf(c), bundle.Options{Roots: w.Roots(), Fetcher: bundle.NewHTTPRekorFetcher(srv.URL)})
	if viaHTTP.ExitCode != 0 {
		t.Fatalf("http online: exit %d %+v", viaHTTP.ExitCode, viaHTTP.Steps)
	}
}

// A REAL production certificate (the SDK's 2026-06-10 fixture) inside a
// bundle, checked with the built-in pins: witness + claim signatures and the
// real FreeTSA token PASS; its Rekor entry predates stored bodies (SKIPPED,
// needs --online) and its claims predate conversation ids, so the honest
// result is INCOMPLETE — never TAMPERED.
func TestRealProductionCertificateWithBuiltInPins(t *testing.T) {
	raw, err := os.ReadFile("../verify/testdata/real-v3-cert.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	c := &bundletest.Cert{RequestID: doc["request_id"].(string), CertificateID: doc["certificate_id"].(string), JSON: raw}
	f := bundletest.Build(bundletest.Spec{ConversationID: "conv-real-fixture", CustomerID: "verify-recon-20260529b", Certs: []*bundletest.Cert{c}})
	roots, err := bundle.ProductionRoots()
	if err != nil {
		t.Fatal(err)
	}
	rep := bundle.Verify("real.zip", f.Zip(), bundle.Options{Roots: roots, Now: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)})
	want := map[string]bundle.Status{"signature": bundle.Pass, "claims": bundle.Pass, "timestamp": bundle.PassNotContentBound, "rekor": bundle.Skipped, "binding": bundle.Skipped}
	for n, st := range want {
		s := stepOf(rep, c.RequestID, n)
		if s == nil || s.Status != st {
			t.Fatalf("%s: got %+v, want %s", n, s, st)
		}
	}
	if rep.ExitCode != 2 {
		t.Fatalf("exit %d, want 2 (INCOMPLETE)", rep.ExitCode)
	}
}

// Opt-in (network): the same real certificate with --online re-fetches its
// Rekor entry from rekor.sigstore.dev and must PASS the Rekor step against the
// built-in public-good key and the built-in witness key.
func TestRealProductionCertificateOnline(t *testing.T) {
	if os.Getenv("LUCAIRN_VERIFY_ONLINE") != "1" {
		t.Skip("set LUCAIRN_VERIFY_ONLINE=1 to contact rekor.sigstore.dev")
	}
	raw, err := os.ReadFile("../verify/testdata/real-v3-cert.fixture.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	c := &bundletest.Cert{RequestID: doc["request_id"].(string), CertificateID: doc["certificate_id"].(string), JSON: raw}
	f := bundletest.Build(bundletest.Spec{ConversationID: "conv-real-fixture", CustomerID: "verify-recon-20260529b", Certs: []*bundletest.Cert{c}})
	roots, _ := bundle.ProductionRoots()
	rep := bundle.Verify("real.zip", f.Zip(), bundle.Options{Roots: roots, Fetcher: bundle.NewHTTPRekorFetcher(bundle.PublicRekorURL)})
	s := stepOf(rep, c.RequestID, "rekor")
	if s == nil || s.Status != bundle.PassNotContentBound {
		t.Fatalf("rekor online: %+v", s)
	}
	t.Logf("rekor online: %s", s.Detail)
}

// RFC 3161 § 2.3 (found by the openssl RED-PROOF): a TSA certificate whose
// time-stamping EKU is not critical must FAIL the timestamp step.
func TestTimestampRejectsNonCriticalEKU(t *testing.T) {
	w, err := bundletest.NewWorldWith("eku", bundletest.WorldOptions{TSAEKUNonCritical: true})
	if err != nil {
		t.Fatal(err)
	}
	c, err := w.NewCert(bundletest.CertOptions{ConversationID: "conv-e", CustomerID: "cust-e", IssuedAt: time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	f := bundletest.Build(bundletest.Spec{ConversationID: "conv-e", CustomerID: "cust-e", Certs: []*bundletest.Cert{c}})
	rep := bundle.Verify("e.zip", f.Zip(), bundle.Options{Roots: w.Roots()})
	if s := stepOf(rep, c.RequestID, "timestamp"); s == nil || s.Status != bundle.Fail || rep.ExitCode != 1 {
		t.Fatalf("non-critical EKU: exit %d %+v", rep.ExitCode, s)
	}
}

// Anchor honesty (gap G2): a passing timestamp or rekor step is ALWAYS the
// not-content-bound state, its reason sentence is printed under it, the
// result summary carries the limitation, and no bare PASS is ever printed
// for those two steps — in every corpus case, clean or mutated.
func TestAnchorStepsNeverPrintBarePass(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	bare := regexp.MustCompile(`(?m)^\s+(timestamp|rekor)\s+PASS(\s+—|\s*$)`)
	sawAnchorPass := false
	for _, c := range co.Cases {
		rep := bundle.Verify(c.Name+".zip", c.Zip, bundle.Options{Roots: co.World.Roots()})
		var buf strings.Builder
		rep.WriteText(&buf)
		out := buf.String()
		if bare.MatchString(out) {
			t.Fatalf("%s: bare PASS printed for an anchor step:\n%s", c.Name, out)
		}
		ran := false
		for _, s := range rep.Steps {
			if s.Name != "timestamp" && s.Name != "rekor" {
				continue
			}
			if s.Status == bundle.Pass {
				t.Fatalf("%s: %s step has status PASS", c.Name, s.Name)
			}
			if s.Status == bundle.PassNotContentBound || s.Status == bundle.Fail {
				ran = true
			}
			if s.Status == bundle.PassNotContentBound {
				sawAnchorPass = true
				line := "  " + fmt.Sprintf("%-16s", s.Name) + " " + bundle.NotContentBoundLabel
				if !strings.Contains(out, line) {
					t.Fatalf("%s: missing %q", c.Name, line)
				}
			}
		}
		if ran {
			if !strings.Contains(out, "LIMITATION: "+bundle.NotContentBoundReason) || len(rep.Limitations) == 0 {
				t.Fatalf("%s: anchor step ran but the summary lacks the limitation", c.Name)
			}
			if n := strings.Count(out, bundle.NotContentBoundReason); n < 2 {
				t.Fatalf("%s: reason printed %d times, want under the step(s) and in the summary", c.Name, n)
			}
		}
	}
	if !sawAnchorPass {
		t.Fatal("corpus produced no passing anchor step")
	}
}
