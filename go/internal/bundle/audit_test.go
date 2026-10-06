package bundle_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/declade/lucairn-sdks/go/internal/anchor"
	"github.com/declade/lucairn-sdks/go/internal/bundle"
	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

// T-1231 S2b: format-2 bundles (audit counter, inclusion proofs, anchored
// audit roots). Design specs/2026-10/design-2026-10-06-t1231-s2b-audit-counter.md §5.3.

func auditWorld(t *testing.T, o bundletest.ScenarioOptions) (*bundletest.World, *bundletest.AuditScenario, bundle.TrustRoots) {
	t.Helper()
	w, err := bundletest.NewWorld("audit-test")
	if err != nil {
		t.Fatal(err)
	}
	sc, err := w.NewAuditScenario(o)
	if err != nil {
		t.Fatal(err)
	}
	roots := w.Roots()
	roots.RequireAnchors = !o.SelfHosted
	return w, sc, roots
}

func stepsNamed(r *bundle.Report, name string) []bundle.Step {
	var out []bundle.Step
	for _, s := range r.Steps {
		if s.Name == name {
			out = append(out, s)
		}
	}
	return out
}

func text(r *bundle.Report) string {
	var b strings.Builder
	r.WriteText(&b)
	return b.String()
}

// EventHashV2 against vectors computed independently (Python hashlib): the
// domain tag, eight "<byte length>:<bytes>" fields, the previous hash as its
// hex characters in front. The second vector has no previous hash and a
// non-ASCII actor (the length prefix counts BYTES).
func TestEventHashV2Vectors(t *testing.T) {
	e := bundle.AuditEvent{
		ConvSeq: 7, ConversationID: "c0ffee00000000000000000000000d04", RequestID: "req-0001",
		EventID: "evt_completion_0001", EventType: "PROXY_INFERENCE_COMPLETED", SourceService: "gateway", Actor: "cust_synthetic_alpha",
		PayloadSHA256:     "666c1aa02e8068c6d5cc1d3295009432c16790bec28ec8ce119d0d1a18d61319",
		PreviousEventHash: strings.Repeat("aa", 32),
	}
	if got := bundle.EventHashV2(e); got != "4f8efac874f2b7801b8dd76c9a0b20bc01495027f2b720b555b189e8bf61f7c1" {
		t.Fatalf("vector 1: %s", got)
	}
	e2 := bundle.AuditEvent{ConvSeq: 1, ConversationID: e.ConversationID, RequestID: "r", EventID: "e", EventType: "T", SourceService: "s",
		Actor: "Zoë", PayloadSHA256: e.PayloadSHA256}
	if got := bundle.EventHashV2(e2); got != "d1cc13d57d963f7b1f4dcbef1bb0aaa34c06333793c51d8645b6b2c47714f815" {
		t.Fatalf("vector 2: %s", got)
	}
	// Every hashed field changes the hash.
	base := bundle.EventHashV2(e)
	for name, mut := range map[string]func(*bundle.AuditEvent){
		"conv_seq": func(x *bundle.AuditEvent) { x.ConvSeq++ }, "conversation_id": func(x *bundle.AuditEvent) { x.ConversationID = bundletest.ConvE },
		"request_id": func(x *bundle.AuditEvent) { x.RequestID += "x" }, "event_id": func(x *bundle.AuditEvent) { x.EventID += "x" },
		"event_type": func(x *bundle.AuditEvent) { x.EventType += "x" }, "source_service": func(x *bundle.AuditEvent) { x.SourceService += "x" },
		"actor": func(x *bundle.AuditEvent) { x.Actor += "x" }, "payload_sha256": func(x *bundle.AuditEvent) { x.PayloadSHA256 = strings.Repeat("0", 64) },
		"previous_event_hash": func(x *bundle.AuditEvent) { x.PreviousEventHash = strings.Repeat("bb", 32) },
		// A field boundary moved: "ab"+"c" vs "a"+"bc" must differ.
		"boundary": func(x *bundle.AuditEvent) { x.EventID, x.EventType = x.EventID+"P", x.EventType[1:] },
	} {
		x := e
		mut(&x)
		if bundle.EventHashV2(x) == base {
			t.Errorf("%s is not inside the hash", name)
		}
	}
}

// The clean format-2 bundle: every audit check is a PASS, by name.
func TestCleanAuditBundleSteps(t *testing.T) {
	_, sc, roots := auditWorld(t, bundletest.ScenarioOptions{})
	rep := bundle.Verify("clean.zip", sc.Clean.Zip(), bundle.Options{Roots: roots})
	if rep.ExitCode != 0 {
		t.Fatalf("clean v2: exit %d %+v", rep.ExitCode, failing(rep))
	}
	for name, want := range map[string]int{
		bundle.StepAuditFiles: 1, bundle.StepAuditConversation: 1, bundle.StepAuditEventHash: 1, bundle.StepAuditContinuity: 1,
		bundle.StepAuditRoot: 2, bundle.StepAuditCounter: 4, bundle.StepAuditInclusion: 4, bundle.StepAuditCertificates: 1,
	} {
		got := stepsNamed(rep, name)
		if len(got) != want {
			t.Errorf("%s: %d steps, want %d", name, len(got), want)
		}
		for _, s := range got {
			if s.Status != bundle.Pass {
				t.Errorf("%s: %s %s", name, s.Status, s.Detail)
			}
		}
	}
	out := text(rep)
	for _, want := range []string{
		"counted requests  4 (audit counter, bundle format 2)",
		"LIMITATION: " + bundle.CounterTailLimitReason,
		"LIMITATION: " + bundle.PreAnchorLimitReason,
		"  - " + bundle.CounterTailLimitReason,
		"seq 1..4, no gap, no duplicate",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("clean v2 text lacks %q", want)
		}
	}
	if strings.Contains(out, bundle.NoAuditRootLimitReason) || strings.Contains(out, "v1 bundles carry no per-conversation request counter") {
		t.Error("clean v2 text carries a v1-only or no-root line")
	}
	if rep.AuditEvents != 4 || rep.AuditRoots != 2 || rep.BundleFormat != 2 {
		t.Errorf("report counts: %d events, %d roots, format %d", rep.AuditEvents, rep.AuditRoots, rep.BundleFormat)
	}
}

// A format-1 bundle is reported exactly as before: the two "not in this
// bundle version" lines, no audit step, no counter limitation, no new JSON key.
func TestFormat1ReportUnchangedByAuditChecks(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	roots := co.World.Roots()
	roots.RequireAnchors = true
	rep := bundle.Verify("clean.zip", co.Clean.Zip(), bundle.Options{Roots: roots})
	out := text(rep)
	if rep.ExitCode != 0 || !strings.Contains(out, "audit-counter    SKIPPED(not in this bundle version)") || !strings.Contains(out, "audit-inclusion  SKIPPED(not in this bundle version)") {
		t.Fatalf("v1 clean: exit %d\n%s", rep.ExitCode, out)
	}
	for _, not := range []string{"counted requests", bundle.CounterTailLimitReason, bundle.PreAnchorLimitReason, bundle.NoAuditRootLimitReason, "audit-root", "audit-files"} {
		if strings.Contains(out, not) {
			t.Errorf("v1 text contains %q", not)
		}
	}
	var js strings.Builder
	if err := rep.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	for _, not := range []string{"bundle_format_version", "audit_counted_requests", "audit_roots_verified"} {
		if strings.Contains(js.String(), not) {
			t.Errorf("v1 JSON contains %q", not)
		}
	}
	if len(rep.NotCovered) != len(bundle.NotCoveredV1) {
		t.Error("v1 NOT COVERED list changed")
	}
}

// Check J: self-hosted without anchoring. Counter checks run and pass; the
// anchor steps are SKIPPED(not anchored) and do not block; the summary says
// no anchored root was verified. Under the hosted policy the same bundle is
// INCOMPLETE.
func TestSelfHostedWithoutAuditRoots(t *testing.T) {
	_, sc, roots := auditWorld(t, bundletest.ScenarioOptions{SelfHosted: true, Conversation: bundletest.ConvF})
	rep := bundle.Verify("self.zip", sc.Clean.Zip(), bundle.Options{Roots: roots})
	if rep.ExitCode != 0 {
		t.Fatalf("self-hosted: exit %d %+v", rep.ExitCode, failing(rep))
	}
	for _, name := range []string{bundle.StepAuditCounter, bundle.StepAuditEventHash, bundle.StepAuditContinuity, bundle.StepAuditCertificates, bundle.StepAuditConversation} {
		for _, s := range stepsNamed(rep, name) {
			if s.Status != bundle.Pass {
				t.Errorf("%s: %s %s", name, s.Status, s.Detail)
			}
		}
	}
	for _, name := range []string{bundle.StepAuditRoot, bundle.StepAuditInclusion} {
		got := stepsNamed(rep, name)
		if len(got) == 0 {
			t.Errorf("%s: no step", name)
		}
		for _, s := range got {
			if s.Status != bundle.Skipped || s.Incomplete || !strings.HasPrefix(s.Detail, "not anchored") {
				t.Errorf("%s: %s blocks=%v %s", name, s.Status, s.Incomplete, s.Detail)
			}
		}
	}
	if out := text(rep); !strings.Contains(out, "LIMITATION: "+bundle.NoAuditRootLimitReason) || strings.Contains(out, "LIMITATION: "+bundle.PreAnchorLimitReason) {
		t.Errorf("self-hosted limitation lines wrong:\n%s", out)
	}
	roots.RequireAnchors = true
	if rep := bundle.Verify("self.zip", sc.Clean.Zip(), bundle.Options{Roots: roots}); rep.ExitCode != bundle.ExitIncomplete {
		t.Fatalf("no roots under the hosted policy: exit %d, want 2", rep.ExitCode)
	}
}

// Check I and the D3 rules. Whether a request was counted is stated by its
// certificate's signed audit claim (conversation_id + conv_seq), not by a
// date in the tool:
//   - claim without a counter, no entry  -> "not tracked", INCOMPLETE;
//   - claim with a counter, no entry, format 2 -> TAMPERED;
//   - claim with a counter, format 1 (downgraded) -> INCOMPLETE;
//   - format 1, claim without a counter  -> as before (VALID).
func TestCountedIsWhatTheSignedClaimSays(t *testing.T) {
	_, sc, roots := auditWorld(t, bundletest.ScenarioOptions{})
	counterStep := func(rep *bundle.Report, c *bundletest.Cert) *bundle.Step {
		return stepOf(rep, c.RequestID, bundle.StepAuditCounter)
	}
	// Not tracked.
	rep := bundle.Verify("x.zip", bundletest.Build(bundletest.Spec{ConversationID: bundletest.ConvD, CustomerID: bundletest.Customer,
		Certs: append([]*bundletest.Cert{sc.Uncounted}, sc.Certs...), Audit: sc.Evidence}).Zip(), bundle.Options{Roots: roots})
	if s := counterStep(rep, sc.Uncounted); rep.ExitCode != bundle.ExitIncomplete || s == nil || s.Status != bundle.Skipped || !s.Incomplete || !strings.HasPrefix(s.Detail, "not tracked") {
		t.Errorf("not tracked: exit %d %+v", rep.ExitCode, s)
	}
	// Counted, entry removed (every position, not only the last).
	for i, c := range sc.Certs {
		f := sc.Clean.Clone()
		seq := sc.Evidence.Events[i].ConvSeq
		drop := func(l []any) []any {
			var out []any
			for _, o := range l {
				if string(o.(map[string]any)["conv_seq"].(json.Number)) != strconv.FormatUint(seq, 10) {
					out = append(out, o)
				}
			}
			return out
		}
		f.EditList(bundle.PathAuditEvents, drop)
		f.EditList(bundle.PathAuditProofs, drop)
		f.Rehash()
		rep := bundle.Verify("x.zip", f.Zip(), bundle.Options{Roots: roots})
		if s := counterStep(rep, c); rep.ExitCode != bundle.ExitTampered || s == nil || s.Status != bundle.Fail || !strings.Contains(s.Detail, "the entry was removed") {
			t.Errorf("entry %d removed: exit %d %+v", seq, rep.ExitCode, s)
		}
	}
	// Downgraded to format 1.
	down := func(f bundletest.Files) []byte {
		for _, p := range bundle.AuditPaths {
			delete(f, p)
		}
		m := f.Manifest()
		m.FormatVersion = bundle.FormatVersion
		f.WriteManifest(m)
		return f.Zip()
	}
	rep = bundle.Verify("v1.zip", down(sc.Clean.Clone()), bundle.Options{Roots: roots})
	if s := counterStep(rep, sc.Certs[0]); rep.ExitCode != bundle.ExitIncomplete || s == nil || !s.Incomplete {
		t.Errorf("downgraded bundle of counted certificates: exit %d %+v", rep.ExitCode, s)
	}
	// A format-1 bundle of certificates that sign no counter is untouched.
	rep = bundle.Verify("v1.zip", bundletest.Build(bundletest.Spec{ConversationID: bundletest.ConvD, CustomerID: bundletest.Customer,
		Certs: []*bundletest.Cert{sc.Uncounted}}).Zip(), bundle.Options{Roots: roots})
	if rep.ExitCode != 0 || counterStep(rep, sc.Uncounted) != nil {
		t.Errorf("format-1 bundle, claim without a counter: exit %d %+v", rep.ExitCode, failing(rep))
	}
	// Counted certificates whose claims do NOT sign the counter (not what the
	// audit service emits): the event_hash still ties entry and certificate.
	_, hashOnly, r2 := auditWorld(t, bundletest.ScenarioOptions{NoSignedCounter: true})
	if rep := bundle.Verify("x.zip", hashOnly.Clean.Zip(), bundle.Options{Roots: r2}); rep.ExitCode != 0 {
		t.Errorf("hash-only binding: exit %d %+v", rep.ExitCode, failing(rep))
	}
}

// The tree size is read from the signed, anchored root artifact and from
// nowhere else. For seq 1's leaf, size+1 has the same path shape, so its path
// leads to the same root: the math cannot tell the two sizes apart, the
// signed artifact can.
func TestTreeSizeComesFromTheSignedArtifactOnly(t *testing.T) {
	_, sc, roots := auditWorld(t, bundletest.ScenarioOptions{})
	r1 := sc.Evidence.Roots[0]
	e1 := sc.Evidence.Events[0]
	p1 := sc.Evidence.Proofs[1]
	if got, err := anchor.AuditInclusionRoot(e1.LeafIndex, r1.TreeSize+1, e1.EventHash, p1.Path); err != nil || !bytes.Equal(got, r1.Root) {
		t.Fatalf("premise: size+1 must share the path shape (%v)", err)
	}
	setProofSize := func(f bundletest.Files, to uint64) {
		f.EditList(bundle.PathAuditProofs, func(l []any) []any {
			for _, o := range l {
				if m := o.(map[string]any); string(m["tree_size"].(json.Number)) == strconv.FormatUint(r1.TreeSize, 10) {
					m["tree_size"] = json.Number(strconv.FormatUint(to, 10))
				}
			}
			return l
		})
	}
	// Proofs alone.
	f := sc.Clean.Clone()
	setProofSize(f, r1.TreeSize+1)
	f.Rehash()
	rep := bundle.Verify("x.zip", f.Zip(), bundle.Options{Roots: roots})
	if s := stepOf(rep, sc.Certs[0].RequestID, bundle.StepAuditInclusion); rep.ExitCode != bundle.ExitTampered || s == nil || s.Status != bundle.Fail || !strings.Contains(s.Detail, "claims tree size") {
		t.Errorf("proof with another tree size: exit %d %+v", rep.ExitCode, s)
	}
	// Proofs and the root entry's tree_size field, consistently.
	f = sc.Clean.Clone()
	setProofSize(f, r1.TreeSize+1)
	f.EditList(bundle.PathAuditRoots, func(l []any) []any {
		l[0].(map[string]any)["tree_size"] = json.Number(strconv.FormatUint(r1.TreeSize+1, 10))
		return l
	})
	f.Rehash()
	rep = bundle.Verify("x.zip", f.Zip(), bundle.Options{Roots: roots})
	if s := stepOf(rep, "bundle", bundle.StepAuditRoot); rep.ExitCode != bundle.ExitTampered || s == nil || s.Status != bundle.Fail {
		t.Errorf("unsigned tree sizes changed consistently: exit %d %+v", rep.ExitCode, s)
	}
	// No inclusion step of an event under that root may PASS.
	for i, c := range sc.Certs[:2] {
		if s := stepOf(rep, c.RequestID, bundle.StepAuditInclusion); s == nil || s.Status == bundle.Pass {
			t.Errorf("event %d: inclusion step %+v although its root did not verify", i+1, s)
		}
	}
}

// Both spellings the reader accepts for one file and one hash produce the
// same verdict as the gateway's own (a bare array, base64 path elements).
func TestAuditFileSpellings(t *testing.T) {
	_, sc, roots := auditWorld(t, bundletest.ScenarioOptions{})
	f := sc.Clean.Clone()
	for path, key := range map[string]string{bundle.PathAuditEvents: "events", bundle.PathAuditProofs: "proofs", bundle.PathAuditRoots: "roots"} {
		f[path] = []byte(`{"` + key + `":` + string(f[path]) + `}`)
	}
	f.Rehash()
	if rep := bundle.Verify("x.zip", f.Zip(), bundle.Options{Roots: roots}); rep.ExitCode != 0 {
		t.Errorf("arrays wrapped in a single-key object: exit %d %+v", rep.ExitCode, failing(rep))
	}
	f = sc.Clean.Clone()
	f.EditList(bundle.PathAuditProofs, func(l []any) []any {
		for _, o := range l {
			m := o.(map[string]any)
			for i, h := range m["path"].([]any) {
				b, _ := base64.StdEncoding.DecodeString(h.(string))
				m["path"].([]any)[i] = hex.EncodeToString(b)
			}
		}
		return l
	})
	f.Rehash()
	if rep := bundle.Verify("x.zip", f.Zip(), bundle.Options{Roots: roots}); rep.ExitCode != 0 {
		t.Errorf("hex path elements: exit %d %+v", rep.ExitCode, failing(rep))
	}
	// An explicit "no proof" entry for a not-yet-anchored event reads as none.
	f = bundletest.Build(bundletest.Spec{ConversationID: bundletest.ConvD, CustomerID: bundletest.Customer, Certs: sc.Certs, Audit: sc.BeforeR2})
	f.EditList(bundle.PathAuditProofs, func(l []any) []any {
		for _, e := range sc.BeforeR2.Events[2:] {
			l = append(l, bundletest.ProofJSON(e.ConvSeq, bundle.AuditProof{LeafIndex: e.LeafIndex}))
		}
		return l
	})
	f.Rehash()
	if rep := bundle.Verify("x.zip", f.Zip(), bundle.Options{Roots: roots}); rep.ExitCode != bundle.ExitIncomplete || len(stepsNamed(rep, bundle.StepAuditFiles)) != 1 || stepsNamed(rep, bundle.StepAuditFiles)[0].Status != bundle.Pass {
		t.Errorf("explicit no-proof entries: exit %d %+v", rep.ExitCode, failing(rep))
	}
}

// D3: when the audit-signed claim itself carries the counter, it must equal
// the entry's; when it does not, only the event_hash binds.
func TestSignedCounterInClaim(t *testing.T) {
	e := bundle.AuditEvent{ConvSeq: 3, ConversationID: bundletest.ConvD, EventHash: strings.Repeat("ab", 32)}
	for name, c := range map[string]struct {
		hash string
		seq  uint64
		conv string
		want bundle.Status
	}{
		"hash only":             {e.EventHash, 0, "", bundle.Pass},
		"hash + matching seq":   {e.EventHash, 3, bundletest.ConvD, bundle.Pass},
		"other seq":             {e.EventHash, 2, bundletest.ConvD, bundle.Fail},
		"other conversation":    {e.EventHash, 3, bundletest.ConvE, bundle.Fail},
		"other hash":            {strings.Repeat("cd", 32), 3, bundletest.ConvD, bundle.Fail},
		"other hash, no seq":    {strings.Repeat("cd", 32), 0, "", bundle.Fail},
		"empty hash in a claim": {"", 3, bundletest.ConvD, bundle.Fail},
	} {
		if st, detail := bundle.AuditCounterStepForTest(c.hash, c.seq, c.conv, e); st != c.want {
			t.Errorf("%s: %s (%s), want %s", name, st, detail, c.want)
		}
	}
	claim := func(seq any) map[string]map[string]any {
		return map[string]map[string]any{
			"0:dsa-bridge:TOKEN_GENERATED": {"/payload/conv_seq": json.Number("9")},
			"1:dsa-audit:EVENTS_RECORDED":  {"/payload/event_hash": e.EventHash, "/payload/conv_seq": seq},
			"2:dsa-ai:EVENTS_RECORDED":     {"/payload/conv_seq": json.Number("8")},
			"3:dsa-audit:TOKEN_GENERATED":  {"/payload/conv_seq": json.Number("7")},
		}
	}
	// Only a dsa-audit EVENTS_RECORDED claim counts, whatever other claims say.
	if n, seq, bad := bundle.AuditClaimsForTest(claim(json.Number("3"))); n != 1 || seq != 3 || bad {
		t.Errorf("claim selection: %d claims, seq %d, malformed %v", n, seq, bad)
	}
	for _, v := range []any{json.Number("0"), json.Number("03"), json.Number("-3"), "three", true, json.Number("99999999999999999999")} {
		if _, seq, bad := bundle.AuditClaimsForTest(claim(v)); seq != 0 || !bad {
			t.Errorf("conv_seq %v: seq %d, malformed %v", v, seq, bad)
		}
	}
}

// The three audit files have one exact shape; anything else is a structural
// failure, never a silently different reading (the manifest's case-variant
// key class, gate record S1 F7).
func TestAuditFilesAreStrict(t *testing.T) {
	_, sc, roots := auditWorld(t, bundletest.ScenarioOptions{})
	ev, pr, rt := bundle.PathAuditEvents, bundle.PathAuditProofs, bundle.PathAuditRoots
	first := func(fn func(o map[string]any)) func([]any) []any {
		return func(l []any) []any { fn(l[0].(map[string]any)); return l }
	}
	rekor := func(fn func(o map[string]any)) func([]any) []any {
		return first(func(o map[string]any) { fn(o["rekor_entry"].(map[string]any)) })
	}
	cases := map[string]func(f bundletest.Files){
		"conv_seq as a string": func(f bundletest.Files) { f.EditList(ev, first(func(o map[string]any) { o["conv_seq"] = "1" })) },
		"conv_seq with a fraction": func(f bundletest.Files) {
			f.EditList(ev, first(func(o map[string]any) { o["conv_seq"] = json.Number("1.0") }))
		},
		"conv_seq with an exponent": func(f bundletest.Files) {
			f.EditList(ev, first(func(o map[string]any) { o["conv_seq"] = json.Number("1e0") }))
		},
		"conv_seq zero": func(f bundletest.Files) {
			f.EditList(ev, first(func(o map[string]any) { o["conv_seq"] = json.Number("0") }))
		},
		"uppercase event_hash": func(f bundletest.Files) {
			f.EditList(ev, first(func(o map[string]any) { o["event_hash"] = strings.ToUpper(o["event_hash"].(string)) }))
		},
		"payload carried": func(f bundletest.Files) { f.EditList(ev, first(func(o map[string]any) { o["payload"] = "{}" })) },
		"key missing":     func(f bundletest.Files) { f.EditList(ev, first(func(o map[string]any) { delete(o, "actor") })) },
		"root_ref null":   func(f bundletest.Files) { f.EditList(ev, first(func(o map[string]any) { o["root_ref"] = nil })) },
		"leaf_index null": func(f bundletest.Files) { f.EditList(ev, first(func(o map[string]any) { o["leaf_index"] = nil })) },
		"root_ref to no root": func(f bundletest.Files) {
			f.EditList(ev, first(func(o map[string]any) { o["root_ref"] = json.Number("999") }))
		},
		"root_ref cleared, proof kept": func(f bundletest.Files) {
			f.EditList(ev, first(func(o map[string]any) { o["root_ref"] = json.Number("0") }))
		},
		"inclusion_path in the entry": func(f bundletest.Files) {
			f.EditList(ev, first(func(o map[string]any) { o["inclusion_path"] = []any{} }))
		},
		"recorded_at not a string": func(f bundletest.Files) {
			f.EditList(ev, first(func(o map[string]any) { o["recorded_at"] = json.Number("5") }))
		},
		"conversation id not hex": func(f bundletest.Files) {
			f.EditList(ev, first(func(o map[string]any) { o["conversation_id"] = "ConvD" }))
		},
		"request_id repeated": func(f bundletest.Files) {
			f.EditList(ev, func(l []any) []any {
				l[1].(map[string]any)["request_id"] = l[0].(map[string]any)["request_id"]
				return l
			})
		},
		"wrapper with a second key": func(f bundletest.Files) { f[ev] = []byte(`{"events":` + string(f[ev]) + `,"Events":[]}`) },
		"wrapper with another key":  func(f bundletest.Files) { f[ev] = []byte(`{"Events":` + string(f[ev]) + `}`) },
		"top-level string":          func(f bundletest.Files) { f[ev] = []byte(`"events"`) },
		"duplicate top-level key":   func(f bundletest.Files) { f[pr] = []byte(`{"proofs":[],"proofs":[]}`) },
		"trailing data":             func(f bundletest.Files) { f[pr] = append(f[pr], []byte(`{}`)...) },
		"path element too short":    func(f bundletest.Files) { f.EditList(pr, first(func(o map[string]any) { o["path"] = []any{"abcd"} })) },
		"path element 33 bytes": func(f bundletest.Files) {
			f.EditList(pr, first(func(o map[string]any) { o["path"] = []any{base64.StdEncoding.EncodeToString(make([]byte, 33))} }))
		},
		"path element uppercase hex": func(f bundletest.Files) {
			f.EditList(pr, first(func(o map[string]any) { o["path"] = []any{strings.Repeat("AB", 32)} }))
		},
		"proof with side flags": func(f bundletest.Files) {
			f.EditList(pr, first(func(o map[string]any) { o["is_right"] = []any{true} }))
		},
		"proof leaf_index differs": func(f bundletest.Files) {
			f.EditList(pr, first(func(o map[string]any) { o["leaf_index"] = json.Number("0") }))
		},
		"proof tree_size as string": func(f bundletest.Files) { f.EditList(pr, first(func(o map[string]any) { o["tree_size"] = "11" })) },
		"second proof for one seq":  func(f bundletest.Files) { f.EditList(pr, func(l []any) []any { return append(l, l[0]) }) },
		"proof for an unlisted seq": func(f bundletest.Files) {
			f.EditList(pr, func(l []any) []any {
				return append(l, bundletest.ProofJSON(9, bundle.AuditProof{LeafIndex: 1, TreeSize: 11}))
			})
		},
		"root id zero":            func(f bundletest.Files) { f.EditList(rt, first(func(o map[string]any) { o["id"] = json.Number("0") })) },
		"second root with one id": func(f bundletest.Files) { f.EditList(rt, func(l []any) []any { return append(l, l[0]) }) },
		"root without its Rekor body": func(f bundletest.Files) {
			f.EditList(rt, rekor(func(o map[string]any) { delete(o, "canonical_body") }))
		},
		"root with an empty SET": func(f bundletest.Files) {
			f.EditList(rt, rekor(func(o map[string]any) { o["signed_entry_timestamp"] = "" }))
		},
		"Rekor index as a string": func(f bundletest.Files) { f.EditList(rt, rekor(func(o map[string]any) { o["log_index"] = "5" })) },
		"Rekor entry extra key": func(f bundletest.Files) {
			f.EditList(rt, rekor(func(o map[string]any) { o["Log_Index"] = json.Number("5") }))
		},
		"root_hash field edited": func(f bundletest.Files) {
			f.EditList(rt, first(func(o map[string]any) { o["root_hash"] = strings.Repeat("00", 32) }))
		},
		"tree_size field edited": func(f bundletest.Files) {
			f.EditList(rt, first(func(o map[string]any) { o["tree_size"] = json.Number("999") }))
		},
		"root removed, references kept": func(f bundletest.Files) { f.EditList(rt, func(l []any) []any { return l[1:] }) },
		"root signature removed":        func(f bundletest.Files) { f.EditList(rt, first(func(o map[string]any) { o["root_signature"] = "" })) },
	}
	for name, mutate := range cases {
		f := sc.Clean.Clone()
		mutate(f)
		f.Rehash()
		rep := bundle.Verify("x.zip", f.Zip(), bundle.Options{Roots: roots})
		if rep.ExitCode != bundle.ExitTampered {
			t.Errorf("%s: exit %d %s, want 1 (TAMPERED): %+v", name, rep.ExitCode, rep.Verdict, failing(rep))
		}
	}
}

// An entry nobody signed must never count: a made-up, self-consistent,
// unanchored counter entry appended to a self-hosted bundle (where no root
// could expose it) is not VALID — it has no certificate, and giving it the
// request id of a real certificate fails that certificate's signed claim.
func TestFabricatedCounterEntry(t *testing.T) {
	_, sc, roots := auditWorld(t, bundletest.ScenarioOptions{SelfHosted: true, Conversation: bundletest.ConvF})
	fake := bundle.AuditEvent{ConvSeq: 5, ConversationID: bundletest.ConvF, RequestID: "made-up-request", EventID: "evt_made_up",
		EventType: "PROXY_INFERENCE_COMPLETED", SourceService: "gateway", Actor: bundletest.Customer,
		PayloadSHA256: strings.Repeat("12", 32), PreviousEventHash: sc.Evidence.Events[3].EventHash}
	fake.EventHash = bundle.EventHashV2(fake)
	f := sc.Clean.Clone()
	f.EditList(bundle.PathAuditEvents, func(l []any) []any { return append(l, bundletest.EventJSON(fake)) })
	f.Rehash()
	if rep := bundle.Verify("x.zip", f.Zip(), bundle.Options{Roots: roots}); rep.ExitCode != bundle.ExitIncomplete {
		t.Errorf("appended made-up entry: exit %d, want 2: %+v", rep.ExitCode, failing(rep))
	}
	// The made-up entry takes the place of a real request's entry (its
	// request id, another seq position is impossible: one entry per request).
	f = sc.Clean.Clone()
	fake.ConvSeq, fake.RequestID, fake.EventID = 4, sc.Certs[3].RequestID, sc.Evidence.Events[3].EventID
	fake.PreviousEventHash = sc.Evidence.Events[3].PreviousEventHash
	fake.EventHash = bundle.EventHashV2(fake)
	f.EditList(bundle.PathAuditEvents, func(l []any) []any { l[3] = bundletest.EventJSON(fake); return l })
	f.Rehash()
	rep := bundle.Verify("x.zip", f.Zip(), bundle.Options{Roots: roots})
	if rep.ExitCode != bundle.ExitTampered {
		t.Errorf("made-up entry under a real request id: exit %d, want 1", rep.ExitCode)
	}
	found := false
	for _, s := range rep.Steps {
		found = found || (s.Scope == sc.Certs[3].RequestID && s.Name == bundle.StepAuditCounter && s.Status == bundle.Fail)
	}
	if !found {
		t.Errorf("the certificate's audit-counter step did not FAIL: %+v", failing(rep))
	}
}

// Each S2b must-detect case is reported by the check it is named for AND by
// nothing unrelated that would mask a missing check: this lists, per case,
// every step that fails or blocks, and requires the named one among them.
// Cases caught by exactly ONE step show that this check alone decides.
func TestAuditCasesAreCaughtByTheNamedCheck(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	roots := co.World.Roots()
	roots.RequireAnchors = true
	single := 0
	for _, c := range co.Cases {
		if c.Step == "" {
			continue
		}
		opt := bundle.Options{Roots: roots}
		rep := bundle.Verify(c.Name+".zip", c.Zip, opt)
		names := map[string]bool{}
		for _, s := range failing(rep) {
			names[s.Name] = true
		}
		if !names[c.Step] {
			t.Errorf("%s: step %q does not report it (reporting: %v)", c.Name, c.Step, names)
		}
		if len(names) == 1 {
			single++
		}
		t.Logf("%-38s exit %d  reported by %v", c.Name, rep.ExitCode, keys(names))
	}
	if single < 8 {
		t.Errorf("only %d S2b cases are decided by a single check", single)
	}
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
