package bundletest

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/bundle"
)

// T-1231 S2b corpus: format-2 bundles (audit counter, inclusion proofs,
// anchored audit roots). Synthetic keys and data only.

// ExpectIncomplete: the case must exit exactly 2 (INCOMPLETE): something is
// missing or cannot be checked, and nothing may be called tampering (e.g. a
// certificate whose signed audit claim carries no counter is "not tracked",
// never TAMPERED).
const ExpectIncomplete = "INCOMPLETE(2)"

// Conversations of the S2b scenarios.
const (
	ConvD = "c0ffee00000000000000000000000d04"
	ConvE = "c0ffee00000000000000000000000e05"
	ConvF = "c0ffee00000000000000000000000f06"
	// ConvG: one request whose certificate carries two signed counter claims.
	ConvG = "c0ffee0000000000000000000000ab07"
)

// AuditScenario is one synthetic counted conversation: four requests of
// ConvD in an audit log that also holds other traffic and two requests of
// ConvE, with two published roots (R1 covers seq 1–2, R2 covers seq 3–4).
type AuditScenario struct {
	Log *AuditLog
	// Certs are ConvD's four certificates (seq 1…4); Other are ConvE's two.
	Certs, Other []*Cert
	// Evidence is ConvD's audit/ content with both roots published;
	// BeforeR2 is the same conversation exported before the second root
	// existed (seq 3 and 4 not yet anchored); OtherEvidence is ConvE's.
	Evidence, BeforeR2, OtherEvidence *Evidence
	// ForgedR1 is a root for R1's tree size whose signature AND Rekor entry
	// were made by a key that is not the audit key; MixedR1 carries the
	// genuine root signature but a Rekor entry made by that other key.
	ForgedR1, MixedR1 *AuditRootPub
	// Uncounted is a genuine ConvD certificate whose request was recorded
	// before counting started (audit claim present, no counter entry).
	Uncounted *Cert
	// Clean is the clean format-2 bundle.
	Clean Files
}

// ScenarioOptions shape an AuditScenario.
type ScenarioOptions struct {
	// NoSignedCounter: the audit claims of counted requests do NOT carry
	// conversation_id + conv_seq (the audit service always signs them, design
	// D3; such a certificate is "not tracked", whatever audit/ lists for it).
	NoSignedCounter bool
	// SelfHosted: no anchoring anywhere — unanchored certificates issued
	// before the binding cutover, no audit root published.
	SelfHosted bool
	// Conversation defaults to ConvD.
	Conversation string
}

// NewAuditScenario builds one scenario in world w.
func (w *World) NewAuditScenario(o ScenarioOptions) (*AuditScenario, error) {
	conv := o.Conversation
	if conv == "" {
		conv = ConvD
	}
	sc := &AuditScenario{Log: w.NewAuditLog()}
	// Must stay in the past: tokens dated in the future FAIL.
	t0 := CorpusCutover.Add(39*time.Hour + 5*time.Minute) // 2026-10-02T15:05Z
	if o.SelfHosted {
		t0 = CorpusCutover.Add(-60 * time.Hour)
	}
	var err error
	mk := func(c string, at time.Time, uncounted bool) *Cert {
		cert, err2 := w.NewCert(CertOptions{ConversationID: c, CustomerID: Customer, IssuedAt: at,
			Bound: !o.SelfHosted, NoAnchors: o.SelfHosted, Audit: sc.Log, Uncounted: uncounted, NoSignedCounter: o.NoSignedCounter})
		if err2 != nil {
			err = err2
		}
		return cert
	}
	publish := func(at time.Time) {
		if o.SelfHosted {
			return
		}
		if _, err2 := sc.Log.Publish(at); err2 != nil {
			err = err2
		}
	}
	sc.Log.Filler(5)
	sc.Uncounted = mk(conv, t0.Add(-30*time.Minute), true)
	c1 := mk(conv, t0, false)
	sc.Log.Filler(2)
	e1 := mk(ConvE, t0.Add(20*time.Second), false)
	c2 := mk(conv, t0.Add(40*time.Second), false)
	r1At := t0.Truncate(time.Hour).Add(time.Hour + 7*time.Second)
	publish(r1At)
	if err != nil {
		return nil, err
	}
	if !o.SelfHosted {
		other := edKey("not the audit key")
		if sc.ForgedR1, err = sc.Log.PublishBy(other, other, r1At); err != nil {
			return nil, err
		}
		if sc.MixedR1, err = sc.Log.PublishBy(w.Services[AuditService], other, r1At); err != nil {
			return nil, err
		}
	}
	sc.Log.Filler(3)
	c3 := mk(conv, t0.Add(70*time.Minute), false)
	e2 := mk(ConvE, t0.Add(71*time.Minute), false)
	c4 := mk(conv, t0.Add(75*time.Minute), false)
	if err != nil {
		return nil, err
	}
	sc.BeforeR2 = sc.Log.Evidence(conv)
	publish(r1At.Add(time.Hour + 4*time.Second))
	if err != nil {
		return nil, err
	}
	sc.Certs, sc.Other = []*Cert{c1, c2, c3, c4}, []*Cert{e1, e2}
	sc.Evidence, sc.OtherEvidence = sc.Log.Evidence(conv), sc.Log.Evidence(ConvE)
	sc.Clean = Build(Spec{ConversationID: conv, CustomerID: Customer, Certs: sc.Certs, Audit: sc.Evidence})
	return sc, nil
}

// certPath is a certificate's path in a bundle.
func certPath(c *Cert) string { return bundle.DirCertificates + c.RequestID + ".json" }

// RemoveCert deletes a certificate file and its manifest entry and re-hashes.
func (f Files) RemoveCert(c *Cert) {
	delete(f, certPath(c))
	m := f.Manifest()
	var keep []bundle.ManifestCert
	for _, e := range m.Certificates {
		if e.RequestID != c.RequestID {
			keep = append(keep, e)
		}
	}
	m.Certificates = keep
	f.WriteManifest(m)
}

func seqOf(o any) string { return string(o.(map[string]any)["conv_seq"].(json.Number)) }

// dropSeq removes the entry with conv_seq seq from an events or proofs list.
func dropSeq(seq uint64) func([]any) []any {
	return func(list []any) []any {
		var out []any
		for _, o := range list {
			if seqOf(o) != fmt.Sprint(seq) {
				out = append(out, o)
			}
		}
		return out
	}
}

// each applies fn to the entry with conv_seq seq.
func each(seq uint64, fn func(o map[string]any)) func([]any) []any {
	return func(list []any) []any {
		for _, o := range list {
			if seqOf(o) == fmt.Sprint(seq) {
				fn(o.(map[string]any))
			}
		}
		return list
	}
}

// rehashEvent recomputes an events.json entry's event_hash from its fields.
func rehashEvent(o map[string]any) {
	seq, _ := o["conv_seq"].(json.Number).Int64()
	s := func(k string) string { return o[k].(string) }
	o["event_hash"] = bundle.EventHashV2(bundle.AuditEvent{
		ConvSeq: uint64(seq), ConversationID: s("conversation_id"), RequestID: s("request_id"), EventID: s("event_id"),
		EventType: s("event_type"), SourceService: s("source_service"), Actor: s("actor"),
		PayloadSHA256: s("payload_sha256"), PreviousEventHash: s("previous_event_hash"),
	})
}

// addAuditCases appends the S2b cases. It mints its certificates AFTER every
// earlier case's, so those stay byte-identical.
func addAuditCases(co *Corpus) error {
	w := co.World
	sc, err := w.NewAuditScenario(ScenarioOptions{})
	if err != nil {
		return err
	}
	self, err := w.NewAuditScenario(ScenarioOptions{SelfHosted: true, Conversation: ConvF})
	if err != nil {
		return err
	}
	co.Audit, co.AuditSelfHosted = sc, self
	for _, c := range sc.Certs {
		e, err := EntryOf(c)
		if err != nil {
			return err
		}
		co.Entries[e.LogIndex] = e
	}
	for i, e := range sc.Log.Entries {
		co.Entries[i] = e
	}
	add := func(name, what, expect, step, detail string, f Files, flags ...string) {
		co.Cases = append(co.Cases, Case{Name: name, What: what, Expect: expect, Zip: f.Zip(), Flags: flags, Step: step, Detail: detail})
	}
	clean := sc.Clean
	c := sc.Certs
	ev, pr, rt := bundle.PathAuditEvents, bundle.PathAuditProofs, bundle.PathAuditRoots
	r1 := sc.Evidence.Roots[0]

	add("S2b-00-clean-v2", "untouched format-2 bundle: 4 counted requests, 4 certificates, 2 anchored audit roots", ExpectValid, "", "", clean.Clone())
	add("S2b-00-clean-v2-online", "the clean format-2 bundle, --online against the synthetic log (certificate and audit-root entries)", ExpectValid, "", "", clean.Clone(),
		"--online", "--rekor-url", RekorURLPlaceholder)

	// Check D. A counted row deleted (as on a staging copy of the audit DB):
	// its entry and proof are gone, its certificate is still there.
	{
		f := clean.Clone()
		f.EditList(ev, dropSeq(2))
		f.EditList(pr, dropSeq(2))
		f.Rehash()
		add("S2b-01-row-deleted", "counted row seq 2 deleted (entry + proof gone, certificate kept); manifest re-hashed", ExpectTampered, bundle.StepAuditContinuity, "seq gap at 2", f)
	}
	// G1 with the counter: certificate, manifest line, entry and proof all removed.
	{
		f := clean.Clone()
		f.EditList(ev, dropSeq(2))
		f.EditList(pr, dropSeq(2))
		f.RemoveCert(c[1])
		add("S2b-01b-row-and-cert-deleted", "G1 on a format-2 bundle: certificate 2 removed with its manifest entry, counter entry and proof; manifest rewritten", ExpectTampered, bundle.StepAuditContinuity, "seq gap at 2", f)
	}
	renumber := func(f Files, rehash bool) {
		f.EditList(ev, dropSeq(2))
		f.EditList(pr, dropSeq(2))
		for _, mv := range [][2]uint64{{3, 2}, {4, 3}} {
			from, to := mv[0], mv[1]
			f.EditList(ev, each(from, func(o map[string]any) {
				o["conv_seq"] = num(to)
				if rehash {
					rehashEvent(o)
				}
			}))
			f.EditList(pr, each(from, func(o map[string]any) { o["conv_seq"] = num(to) }))
		}
		f.RemoveCert(c[1])
	}
	{
		f := clean.Clone()
		renumber(f, false)
		add("S2b-02-renumbered", "certificate 2 + its counter entry removed and seq 3,4 renumbered to 2,3 (event_hash kept); manifest rewritten", ExpectTampered, bundle.StepAuditEventHash, "does not recompute", f)
	}
	{
		f := clean.Clone()
		renumber(f, true)
		add("S2b-02b-renumbered-rehashed", "as S2b-02, and the renumbered entries' event_hash recomputed so they are self-consistent; manifest rewritten", ExpectTampered, bundle.StepAuditCounter, "counted as seq 3", f)
	}
	{
		f := clean.Clone()
		f.EditList(ev, each(3, func(o map[string]any) { o["conv_seq"] = num(2) }))
		f.Rehash()
		add("S2b-03-duplicate-seq", "counter entry seq 3 renumbered to 2 (two entries carry seq 2); manifest re-hashed", ExpectTampered, bundle.StepAuditContinuity, "duplicate seq 2", f)
	}
	// Check F.
	{
		f := clean.Clone()
		var p1, p2 any
		f.EditList(pr, func(l []any) []any {
			for _, o := range l {
				switch seqOf(o) {
				case "1":
					p1 = o.(map[string]any)["path"]
				case "2":
					p2 = o.(map[string]any)["path"]
				}
			}
			return l
		})
		f.EditList(pr, each(1, func(o map[string]any) { o["path"] = p2 }))
		f.EditList(pr, each(2, func(o map[string]any) { o["path"] = p1 }))
		f.Rehash()
		add("S2b-04-proofs-swapped", "inclusion paths of seq 1 and seq 2 (same root) swapped; manifest re-hashed", ExpectTampered, bundle.StepAuditInclusion, "", f)
	}
	{
		f := clean.Clone()
		f.EditList(ev, each(2, func(o map[string]any) { o["leaf_index"] = num(0) }))
		f.EditList(pr, each(2, func(o map[string]any) { o["leaf_index"] = num(0) }))
		f.Rehash()
		add("S2b-04b-leaf-index-edited", "leaf_index of seq 2 changed to another leaf of the same tree, in the entry and in its proof; manifest re-hashed", ExpectTampered, bundle.StepAuditInclusion, "", f)
	}
	{
		f := clean.Clone()
		f.EditList(pr, each(1, func(o map[string]any) {
			path := o["path"].([]any)
			b, _ := hex.DecodeString(path[0].(string))
			b[7] ^= 0x01
			path[0] = hex.EncodeToString(b)
		}))
		f.Rehash()
		add("S2b-04e-path-byte-flipped", "one bit of one sibling hash in the inclusion path of seq 1 flipped (path length unchanged); manifest re-hashed", ExpectTampered, bundle.StepAuditInclusion, "does not lead", f)
	}
	// The tree size comes from the SIGNED root artifact only. Tree size
	// r1.TreeSize+1 has the same path shape for seq 1's leaf, so the path
	// alone would still lead to the root: only the comparison with the signed
	// artifact catches an unsigned size that differs.
	{
		f := clean.Clone()
		f.EditList(pr, each(1, func(o map[string]any) { o["tree_size"] = num(r1.TreeSize + 1) }))
		f.Rehash()
		add("S2b-04c-proof-tree-size-differs", "the inclusion proof of seq 1 claims another tree size than the signed root artifact (a size with the same path shape); manifest re-hashed", ExpectTampered, bundle.StepAuditInclusion, "claims tree size", f)
	}
	{
		f := clean.Clone()
		f.EditList(pr, func(l []any) []any {
			for _, o := range l {
				if m := o.(map[string]any); string(m["tree_size"].(json.Number)) == fmt.Sprint(r1.TreeSize) {
					m["tree_size"] = num(r1.TreeSize + 1)
				}
			}
			return l
		})
		f.EditList(rt, func(l []any) []any { l[0].(map[string]any)["tree_size"] = num(r1.TreeSize + 1); return l })
		f.Rehash()
		add("S2b-04d-unsigned-tree-sizes-agree", "the root entry's tree_size field AND every proof under it changed to the same other size (the unsigned copies agree with each other, not with the signed artifact); manifest re-hashed", ExpectTampered, bundle.StepAuditRoot, "differ from the signed root artifact", f)
	}
	// Check G.
	firstRoot := func(fn func(o map[string]any)) func([]any) []any {
		return func(l []any) []any { fn(l[0].(map[string]any)); return l }
	}
	as := func(pub *AuditRootPub) map[string]any {
		o := RootJSON(pub)
		o["id"] = num(r1.ID)
		return o
	}
	{
		f := clean.Clone()
		wrong := hex.EncodeToString(sc.Evidence.Roots[1].Root)
		f.EditList(rt, firstRoot(func(o map[string]any) {
			o["root_hash"] = wrong
			o["root_artifact"] = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("lucairn.audit-root/v1\n%d\n%s\n", r1.TreeSize, wrong)))
		}))
		f.Rehash()
		add("S2b-05-wrong-root-in-artifact", "root artifact of the first root rewritten to name another root hash (root_hash field too); manifest re-hashed", ExpectTampered, bundle.StepAuditRoot, "", f)
	}
	{
		f := clean.Clone()
		f.EditList(rt, func(l []any) []any { l[0] = as(sc.ForgedR1); return l })
		f.Rehash()
		add("S2b-06-root-non-pinned-key", "first root replaced by one for the same tree, signed and logged in Rekor by a key that is not the pinned audit key; manifest re-hashed", ExpectTampered, bundle.StepAuditRoot, "root signature does not verify", f)
	}
	{
		f := clean.Clone()
		f.EditList(rt, func(l []any) []any { l[0] = as(sc.MixedR1); return l })
		f.Rehash()
		add("S2b-06b-root-rekor-entry-other-key", "first root keeps its genuine signature, but its Rekor entry (valid in the log) was made by another key; manifest re-hashed", ExpectTampered, bundle.StepAuditRoot, "not logged by the pinned", f)
	}
	{
		f := clean.Clone()
		f.EditList(rt, func(l []any) []any {
			l[0].(map[string]any)["rekor_entry"] = l[1].(map[string]any)["rekor_entry"]
			return l
		})
		f.Rehash()
		add("S2b-07-rekor-entry-other-artifact", "first root's Rekor entry replaced by the second root's (genuine audit-key entry for a different artifact); manifest re-hashed", ExpectTampered, bundle.StepAuditRoot, "another artifact", f)
	}
	// audit/ stripped from a format-2 bundle.
	strip := func(f Files) {
		for _, p := range bundle.AuditPaths {
			delete(f, p)
		}
	}
	{
		f := clean.Clone()
		strip(f)
		f.Rehash()
		add("S2b-08-audit-stripped", "the three audit/ files removed from a format-2 bundle; manifest rewritten (still format_version 2)", ExpectTampered, "manifest", "audit/events.json", f)
	}
	{
		f := clean.Clone()
		strip(f)
		m := f.Manifest()
		m.FormatVersion = bundle.FormatVersion
		f.WriteManifest(m)
		add("S2b-08b-downgraded-to-v1", "audit/ removed AND format_version rewritten to 1: a format-1 bundle of certificates whose signed audit claims say they were counted", ExpectIncomplete, bundle.StepAuditCounter, "format-1 bundle", f)
	}
	// Check B.
	{
		f := clean.Clone()
		f.EditList(ev, each(3, func(o map[string]any) { o["actor"] = Customer2 }))
		f.Rehash()
		add("S2b-09-event-field-edited", "actor of counter entry seq 3 edited (its recomputed v2 hash differs); manifest re-hashed", ExpectTampered, bundle.StepAuditEventHash, "does not recompute", f)
	}
	{
		f := clean.Clone()
		f.EditList(ev, each(3, func(o map[string]any) { o["actor"] = Customer2; rehashEvent(o) }))
		f.Rehash()
		add("S2b-09b-event-field-edited-rehashed", "as S2b-09 with event_hash recomputed (self-consistent entry the audit key never signed); manifest re-hashed", ExpectTampered, bundle.StepAuditCounter, "counted as seq 3", f)
	}
	// Check C: a GENUINE entry (with its proof) of another conversation.
	{
		f := clean.Clone()
		foreign := sc.OtherEvidence.Events[1]
		f.EditList(ev, func(l []any) []any {
			for i, o := range l {
				if seqOf(o) == "2" {
					l[i] = EventJSON(foreign)
				}
			}
			return l
		})
		f.EditList(pr, func(l []any) []any {
			for i, o := range l {
				if seqOf(o) == "2" {
					l[i] = ProofJSON(2, sc.OtherEvidence.Proofs[2])
				}
			}
			return l
		})
		f.Rehash()
		add("S2b-10-entry-other-conversation", "counter entry seq 2 replaced by the genuine seq-2 entry (and proof) of another conversation; manifest re-hashed", ExpectTampered, bundle.StepAuditConversation, "another conversation", f)
	}
	// Check I: "not tracked" is INCOMPLETE, never TAMPERED.
	add("S2b-11-cert-without-counter-entry", "a genuine certificate of this conversation whose request was recorded before counting started (its signed audit claim carries no counter; no counter entry)", ExpectIncomplete, bundle.StepAuditCounter, "not tracked",
		Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: append([]*Cert{sc.Uncounted}, c...), Audit: sc.Evidence}))
	// Check E — closes G1: a certificate dropped with its manifest entry.
	{
		f := clean.Clone()
		f.RemoveCert(c[2])
		add("S2b-12-counted-without-cert", "G1 closed: certificate 3 removed TOGETHER with its manifest entry, digests recomputed; the counter entry remains", ExpectIncomplete, bundle.StepAuditCertificates, "request seq 3 has no certificate", f)
	}
	// Check H.
	add("S2b-13-not-yet-anchored", "bundle exported before the second root was published: seq 3 and 4 are newer than the latest anchored audit root", ExpectIncomplete, bundle.StepAuditInclusion, "not yet anchored",
		Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: c, Audit: sc.BeforeR2}))
	// Check J.
	add("S2b-14-self-hosted-no-roots", "self-hosted deployment without anchoring: counter checks run, audit-root and audit-inclusion SKIPPED(not anchored) (run with --allow-unanchored)", ExpectValid, "", "",
		self.Clean.Clone(), FlagAllowUnanchored)
	{
		f := clean.Clone()
		f.EditList(rt, func([]any) []any { return []any{} })
		f.EditList(pr, func([]any) []any { return []any{} })
		f.EditList(ev, func(l []any) []any {
			for _, o := range l {
				o.(map[string]any)["root_ref"] = num(0)
			}
			return l
		})
		f.Rehash()
		add("S2b-14b-roots-stripped-hosted", "every root, proof and root reference removed from a hosted bundle (hosted policy: anchoring required); manifest re-hashed", ExpectIncomplete, bundle.StepAuditInclusion, "not anchored: the bundle carries no audit root", f)
	}
	// D3: the certificate's own signed claim says "counted, seq 4".
	{
		f := clean.Clone()
		f.EditList(ev, dropSeq(4))
		f.EditList(pr, dropSeq(4))
		f.Rehash()
		add("S2b-15-last-entry-removed-cert-kept", "the LAST counter entry and its proof removed, its certificate kept (the certificate's signed audit claim states seq 4); manifest re-hashed", ExpectTampered, bundle.StepAuditCounter, "counted as seq 4", f)
	}
	{
		f := clean.Clone()
		f.EditList(ev, each(1, func(o map[string]any) { o["Conv_Seq"] = num(9) }))
		f.Rehash()
		add("S2b-16-case-variant-key", "a counter entry carries an extra case-variant key Conv_Seq; manifest re-hashed", ExpectTampered, bundle.StepAuditFiles, "Conv_Seq", f)
	}

	// ---- Fix round 1 of SDK #79 (gate record "Sol #79"): G1-G5 ----
	// Minted AFTER every scenario above, so those stay as they were.
	if err := addAuditFixRound1Cases(co, sc, add); err != nil {
		return err
	}

	// Documented limit — measured, expected to exit 0.
	{
		f := clean.Clone()
		f.EditList(ev, dropSeq(4))
		f.EditList(pr, dropSeq(4))
		f.RemoveCert(c[3])
		add("G4-tail-cut", "the LAST request cut off: certificate 4, its manifest entry, counter entry and proof removed (the counter cannot show that N is the last request; printed as a LIMITATION)", ExpectKnownGap, "", "", f)
	}
	return nil
}

// addAuditFixRound1Cases appends the cases of fix round 1 of SDK #79.
func addAuditFixRound1Cases(co *Corpus, sc *AuditScenario, add func(name, what, expect, step, detail string, f Files, flags ...string)) error {
	w := co.World
	clean := sc.Clean
	ev, pr, rt := bundle.PathAuditEvents, bundle.PathAuditProofs, bundle.PathAuditRoots

	// G1 (Sol P1, T8). "Counted" is what the certificate's SIGNED claim says.
	// A scenario whose audit claims do not sign the counter, with genuine v2
	// entries, proofs and roots for the same requests (every event_hash
	// matches its certificate's claim): the entries are not accepted on the
	// hash alone -> "not tracked", INCOMPLETE.
	hashOnly, err := w.NewAuditScenario(ScenarioOptions{NoSignedCounter: true})
	if err != nil {
		return err
	}
	add("S2b-17-entry-claim-without-counter", "every counter entry is genuine and its event_hash equals its certificate's signed audit claim, but no claim signs conversation_id + conv_seq (the certificates do not say they were counted)",
		ExpectIncomplete, bundle.StepAuditCounter, "not tracked", hashOnly.Clean.Clone())
	// The other half of the rule: an entry that gives a number to a request
	// whose signed claim carries no counter AND names another event_hash.
	{
		fake := bundle.AuditEvent{ConvSeq: 5, ConversationID: ConvD, RequestID: sc.Uncounted.RequestID, EventID: "evt_made_up_for_uncounted",
			EventType: "PROXY_INFERENCE_COMPLETED", SourceService: "gateway", Actor: Customer,
			PayloadSHA256: hex.EncodeToString(make([]byte, 32)), PreviousEventHash: sc.Evidence.Events[3].EventHash}
		fake.EventHash = bundle.EventHashV2(fake)
		f := Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: append([]*Cert{sc.Uncounted}, sc.Certs...), Audit: sc.Evidence})
		f.EditList(ev, func(l []any) []any { return append(l, EventJSON(fake)) })
		f.Rehash()
		add("S2b-17b-entry-for-uncounted-request", "a self-consistent counter entry (seq 5) added under the request id of a certificate whose signed audit claim carries no counter and names another event_hash; manifest re-hashed",
			ExpectTampered, bundle.StepAuditCounter, "no signature of this certificate covers", f)
	}

	// G2 (Sol P2, T1). One certificate, two VALID audit-signed claims for the
	// same audit row: one signs seq 1, the other seq 2. The bundle has the
	// one entry (seq 1). Every signed counter claim needs its own entry.
	{
		log := w.NewAuditLog()
		log.Filler(3)
		at := CorpusCutover.Add(41*time.Hour + 10*time.Minute)
		two, err := w.NewCert(CertOptions{ConversationID: ConvG, CustomerID: Customer, IssuedAt: at, Bound: true, Audit: log, ExtraAuditSeq: 2})
		if err != nil {
			return err
		}
		log.Filler(2)
		if _, err := log.Publish(at.Truncate(time.Hour).Add(time.Hour + 9*time.Second)); err != nil {
			return err
		}
		add("S2b-18-two-counter-claims-one-entry", "one certificate with two valid audit-signed claims for the same audit row, signing seq 1 and seq 2; the bundle holds the one counter entry (seq 1)",
			ExpectTampered, bundle.StepAuditCounter, "counted as seq 2",
			Build(Spec{ConversationID: ConvG, CustomerID: Customer, Certs: []*Cert{two}, Audit: log.Evidence(ConvG)}))
	}

	// G3 (Sol P2, T11). The Rekor inclusion-proof JSON is read as ONE strict
	// document. A wrong rootHash followed by a duplicate, genuine rootHash: a
	// lenient decoder takes the later one and verifies.
	dupRootHash := func(proofB64 string) string {
		raw, err := base64.StdEncoding.DecodeString(proofB64)
		if err != nil {
			panic(err)
		}
		const key = `"rootHash":`
		if strings.Count(string(raw), key) != 1 {
			panic("synthetic inclusion proof: rootHash key not found exactly once")
		}
		wrong := key + `"` + strings.Repeat("00", 32) + `",`
		return base64.StdEncoding.EncodeToString([]byte(strings.Replace(string(raw), key, wrong+key, 1)))
	}
	{
		f := clean.Clone()
		f.EditList(rt, func(l []any) []any {
			re := l[0].(map[string]any)["rekor_entry"].(map[string]any)
			re["inclusion_proof"] = dupRootHash(re["inclusion_proof"].(string))
			return l
		})
		f.Rehash()
		add("S2b-19-root-proof-duplicate-key", "the first audit root's Rekor inclusion proof carries rootHash twice: a wrong value, then the genuine one; manifest re-hashed",
			ExpectTampered, bundle.StepAuditRoot, "duplicate object key", f)
	}
	{
		f := clean.Clone()
		p := certPath(sc.Certs[0])
		var doc map[string]any
		if err := json.Unmarshal(f[p], &doc); err != nil {
			return err
		}
		tl := doc["attestation"].(map[string]any)["transparency_log"].(map[string]any)
		tl["inclusion_proof"] = dupRootHash(tl["inclusion_proof"].(string))
		f[p], _ = json.MarshalIndent(doc, "", "  ")
		f.Rehash()
		add("S2b-19b-cert-proof-duplicate-key", "the same duplicate rootHash in the Rekor inclusion proof of a CERTIFICATE (the certificate and the audit-root path share one decoder); manifest re-hashed",
			ExpectTampered, "rekor", "duplicate object key", f)
	}

	// G4 (orchestrator decision on Sol P2, T4). A format-2 bundle without any
	// certificate stays TAMPERED, as in format 1 ("at least one certificate"),
	// whatever its audit/ folder says.
	{
		f := clean.Clone()
		for _, c := range sc.Certs {
			f.RemoveCert(c)
		}
		add("S2b-20-zero-certificates", "every certificate and its manifest entry removed from a format-2 bundle; the audit/ folder (4 counted requests) is kept; manifest rewritten",
			ExpectTampered, "certificate-list", "contains no certificate", f)
	}

	// G5 (api-contract.md section 2a). One form per file, one spelling per hash.
	bare := func(f Files, path string) {
		b, _ := json.MarshalIndent(f.List(path), "", "  ")
		f[path] = append(b, '\n')
	}
	{
		f := clean.Clone()
		for _, p := range bundle.AuditPaths {
			bare(f, p)
		}
		f.Rehash()
		add("S2b-21-audit-files-bare-arrays", "each audit/*.json file is a bare JSON array instead of the object with its one named key; manifest re-hashed",
			ExpectTampered, bundle.StepAuditFiles, "single key", f)
	}
	{
		f := clean.Clone()
		f.PutJSON(pr, map[string]any{"inclusion_proofs": f.List(pr)})
		f.Rehash()
		add("S2b-21b-audit-file-other-key", "audit/proofs.json holds its array under the key inclusion_proofs instead of proofs; manifest re-hashed",
			ExpectTampered, bundle.StepAuditFiles, "single key", f)
	}
	respell := func(f Files, fn func(raw []byte) string) {
		f.EditList(pr, func(l []any) []any {
			for _, o := range l {
				path := o.(map[string]any)["path"].([]any)
				for i, h := range path {
					b, err := hex.DecodeString(h.(string))
					if err != nil {
						panic(err)
					}
					path[i] = fn(b)
				}
			}
			return l
		})
		f.Rehash()
	}
	{
		f := clean.Clone()
		respell(f, base64.StdEncoding.EncodeToString)
		add("S2b-21c-proof-path-base64", "every inclusion path element written as standard base64 of the same 32 bytes instead of lowercase hex; manifest re-hashed",
			ExpectTampered, bundle.StepAuditFiles, "64 lowercase hex", f)
	}
	{
		f := clean.Clone()
		respell(f, func(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) })
		add("S2b-21d-proof-path-uppercase-hex", "every inclusion path element written as upper-case hex of the same 32 bytes; manifest re-hashed",
			ExpectTampered, bundle.StepAuditFiles, "64 lowercase hex", f)
	}
	return nil
}
