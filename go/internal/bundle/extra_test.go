package bundle_test

import (
	"bytes"
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

	"github.com/declade/lucairn-sdks/go/internal/anchor"
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

// Anchor honesty (gap G2): a passing timestamp or rekor step is ALWAYS one
// of the two labelled states — PASS (genuine anchor, not content-bound) or,
// for binding-v1 anchors (T-1231 S2a), PASS (content-bound) — never a bare
// PASS. Whenever a not-content-bound step passed, its reason sentence is
// printed under it and the summary carries the limitation; a run whose
// anchors are ALL content-bound carries no such limitation.
func TestAnchorStepsNeverPrintBarePass(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	bare := regexp.MustCompile(`(?m)^\s+(timestamp|rekor)\s+PASS(\s+—|\s*$)`)
	sawAnchorPass, sawBoundPass := false, false
	for _, c := range co.Cases {
		rep := bundle.Verify(c.Name+".zip", c.Zip, bundle.Options{Roots: co.World.Roots()})
		var buf strings.Builder
		rep.WriteText(&buf)
		out := buf.String()
		if bare.MatchString(out) {
			t.Fatalf("%s: bare PASS printed for an anchor step:\n%s", c.Name, out)
		}
		notBound, bound := false, false
		for _, s := range rep.Steps {
			if s.Name != "timestamp" && s.Name != "rekor" {
				continue
			}
			if s.Status == bundle.Pass {
				t.Fatalf("%s: %s step has status PASS", c.Name, s.Name)
			}
			if s.Status == bundle.PassNotContentBound {
				sawAnchorPass, notBound = true, true
				line := "  " + fmt.Sprintf("%-16s", s.Name) + " " + bundle.NotContentBoundLabel
				if !strings.Contains(out, line) {
					t.Fatalf("%s: missing %q", c.Name, line)
				}
			}
			if s.Status == bundle.PassContentBound {
				sawBoundPass, bound = true, true
				line := "  " + fmt.Sprintf("%-16s", s.Name) + " " + bundle.ContentBoundLabel
				if !strings.Contains(out, line) {
					t.Fatalf("%s: missing %q", c.Name, line)
				}
			}
		}
		if notBound {
			if !strings.Contains(out, "LIMITATION: "+bundle.NotContentBoundReason) || len(rep.Limitations) == 0 {
				t.Fatalf("%s: a not-content-bound anchor passed but the summary lacks the limitation", c.Name)
			}
			if n := strings.Count(out, bundle.NotContentBoundReason); n < 2 {
				t.Fatalf("%s: reason printed %d times, want under the step(s) and in the summary", c.Name, n)
			}
		}
		if bound && !notBound && rep.ExitCode == 0 && strings.Contains(out, bundle.NotContentBoundReason) {
			t.Fatalf("%s: every anchor is content-bound, yet the not-content-bound limitation is printed", c.Name)
		}
	}
	if !sawBoundPass {
		t.Fatal("corpus produced no content-bound anchor step")
	}
	if !sawAnchorPass {
		t.Fatal("corpus produced no passing anchor step")
	}
}

// The timestamp line names only the signer's common name; the full DN stays
// in the JSON step.
func TestTimestampLinePrintsSignerCNOnly(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	roots := co.World.Roots()
	roots.RequireAnchors = true
	for _, c := range co.Cases {
		if c.Expect != bundletest.ExpectValid {
			continue
		}
		rep := bundle.Verify(c.Name+".zip", c.Zip, bundle.Options{Roots: roots})
		for _, s := range rep.Steps {
			if s.Name != "timestamp" || s.Status != bundle.PassNotContentBound {
				continue
			}
			if !strings.Contains(s.Detail, "signer Synthetic TSA (test only)") || strings.Contains(s.Detail, "CN=") {
				t.Fatalf("timestamp detail should carry the CN only: %q", s.Detail)
			}
			if !strings.Contains(s.SignerDN, "CN=Synthetic TSA (test only)") {
				t.Fatalf("signer_dn should keep the full DN: %q", s.SignerDN)
			}
			var buf bytes.Buffer
			if err := rep.WriteJSON(&buf); err != nil || !strings.Contains(buf.String(), `"signer_dn"`) {
				t.Fatalf("JSON lacks signer_dn: %v", err)
			}
			return
		}
	}
	t.Fatal("no valid case with a timestamp step")
}

// T-1231 S2a: the built-in hosted pins carry the binding cutover.
func TestProductionRootsCarryTheBindingCutover(t *testing.T) {
	roots, err := bundle.ProductionRoots()
	if err != nil {
		t.Fatal(err)
	}
	if !roots.BindingRequiredAfter.Equal(anchor.BindingV1Cutover) {
		t.Fatalf("hosted roots cutover %v, want %v", roots.BindingRequiredAfter, anchor.BindingV1Cutover)
	}
}

// T-1231 S2a: a binding-v1 certificate whose witness key is not pinned
// cannot be content-checked: its timestamp is SKIPPED (blocking), never a
// pass — the binding digest needs the signature-verified signable.
func TestBoundCertWithoutPinnedWitnessIsNotPassed(t *testing.T) {
	w, err := bundletest.NewWorld("bound-nokey")
	if err != nil {
		t.Fatal(err)
	}
	c, err := w.NewCert(bundletest.CertOptions{ConversationID: "conv-b", CustomerID: "cust-b", IssuedAt: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC), Bound: true})
	if err != nil {
		t.Fatal(err)
	}
	f := bundletest.Build(bundletest.Spec{ConversationID: "conv-b", CustomerID: "cust-b", Certs: []*bundletest.Cert{c}})
	roots := w.Roots()
	roots.WitnessKeys = nil
	rep := bundle.Verify("b.zip", f.Zip(), bundle.Options{Roots: roots})
	s := stepOf(rep, c.RequestID, "timestamp")
	if s == nil || s.Status != bundle.Skipped || !s.Incomplete || rep.ExitCode != 2 {
		t.Fatalf("bound cert without a pinned witness key: exit %d %+v", rep.ExitCode, s)
	}
}

// T-1231 S2a fix round — Sol #747 P1 shape (gate "Round-1 verdict S2a"):
// another bound certificate's anchors relabelled legacy with cert_hash := its
// binding digest. After the cutover the downgrade guard makes it TAMPERED
// (exit 1); before the cutover the Rekor entry for sha512(cert_hash) gives it
// away (exit 1); with that entry dropped the hosted policy reports the
// missing anchor (exit 2).
func TestSolP1RelabelledAnchors_ExitCodes(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		exit int
		step string
	}{
		"S2a-10-solp1-relabelled-post-cutover": {1, "timestamp"},
		"S2a-11-solp1-relabelled-pre-cutover":  {1, "rekor"},
		"S2a-12-solp1-pre-cutover-tsa-only":    {2, "rekor"},
	}
	seen := 0
	for _, c := range co.Cases {
		w, ok := want[c.Name]
		if !ok {
			continue
		}
		seen++
		rep := bundle.Verify(c.Name+".zip", c.Zip, bundle.Options{Roots: co.World.Roots()})
		if rep.ExitCode != w.exit {
			var buf strings.Builder
			rep.WriteText(&buf)
			t.Errorf("%s: exit %d, want %d\n%s", c.Name, rep.ExitCode, w.exit, buf.String())
			continue
		}
		bad := false
		for _, s := range rep.Steps {
			if s.Name == w.step && (s.Status == bundle.Fail || (w.exit == 2 && s.Status == bundle.Skipped && s.Incomplete)) {
				bad = true
			}
		}
		if !bad {
			t.Errorf("%s: no %s step carries the finding", c.Name, w.step)
		}
	}
	if seen != len(want) {
		t.Fatalf("corpus has %d of the %d Sol P1 cases", seen, len(want))
	}
}

// T-1231 S2a fix round (D3): a binding-v1 certificate whose TSA rail failed
// keeps cert_hash + the marker without a token. Its Rekor entry is still
// content-bound. With anchors not required (--allow-unanchored) the bundle is
// VALID; under the hosted policy the missing timestamp is INCOMPLETE.
func TestRekorOnlyBoundCertificate(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	ro := co.RekorOnly
	if ro == nil {
		t.Fatal("corpus lacks its Rekor-only certificate")
	}
	f := bundletest.Build(bundletest.Spec{ConversationID: bundletest.ConvA, CustomerID: bundletest.Customer, Certs: []*bundletest.Cert{ro}})
	roots := co.World.Roots()
	for _, tc := range []struct {
		name    string
		require bool
		exit    int
	}{{"anchors not required", false, 0}, {"hosted policy", true, 2}} {
		roots.RequireAnchors = tc.require
		rep := bundle.Verify("ro.zip", f.Zip(), bundle.Options{Roots: roots})
		var buf strings.Builder
		rep.WriteText(&buf)
		if rep.ExitCode != tc.exit {
			t.Fatalf("%s: exit %d, want %d\n%s", tc.name, rep.ExitCode, tc.exit, buf.String())
		}
		if s := stepOf(rep, ro.RequestID, "rekor"); s == nil || s.Status != bundle.PassContentBound {
			t.Fatalf("%s: rekor must be PASS (content-bound), got %+v\n%s", tc.name, s, buf.String())
		}
		if s := stepOf(rep, ro.RequestID, "timestamp"); s == nil || s.Status != bundle.Skipped {
			t.Fatalf("%s: timestamp must be SKIPPED (not anchored), got %+v", tc.name, s)
		}
	}
	// Tamper: the recorded cert_hash is an input to H — the entry no longer matches.
	edited := bundletest.Build(bundletest.Spec{ConversationID: bundletest.ConvA, CustomerID: bundletest.Customer, Certs: []*bundletest.Cert{ro}})
	p := bundle.DirCertificates + ro.RequestID + ".json"
	var doc map[string]any
	if err := json.Unmarshal(edited[p], &doc); err != nil {
		t.Fatal(err)
	}
	ts := doc["attestation"].(map[string]any)["timestamp"].(map[string]any)
	h, _ := base64.StdEncoding.DecodeString(ts["cert_hash"].(string))
	h[0] ^= 1
	ts["cert_hash"] = base64.StdEncoding.EncodeToString(h)
	edited[p], _ = json.Marshal(doc)
	edited.Rehash()
	roots.RequireAnchors = false
	if rep := bundle.Verify("ro-t.zip", edited.Zip(), bundle.Options{Roots: roots}); rep.ExitCode != 1 {
		t.Fatalf("edited cert_hash on a Rekor-only certificate: exit %d, want 1", rep.ExitCode)
	}
	// Downgrade on a Rekor-only certificate issued after the cutover: the
	// marker stripped to legacy is TAMPERED even though the remaining Rekor
	// entry is the bound one (found by the execution proof; a994d083 said VALID).
	stripped := bundletest.Build(bundletest.Spec{ConversationID: bundletest.ConvA, CustomerID: bundletest.Customer, Certs: []*bundletest.Cert{ro}})
	if err := json.Unmarshal(stripped[p], &doc); err != nil {
		t.Fatal(err)
	}
	doc["attestation"].(map[string]any)["timestamp"].(map[string]any)["hash_algorithm"] = "SHA-256"
	stripped[p], _ = json.Marshal(doc)
	stripped.Rehash()
	if rep := bundle.Verify("ro-s.zip", stripped.Zip(), bundle.Options{Roots: roots}); rep.ExitCode != 1 {
		t.Fatalf("binding marker stripped on a post-cutover Rekor-only certificate: exit %d, want 1", rep.ExitCode)
	}
}
