package bundletest

import (
	"encoding/json"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/bundle"
)

// NewCleaningScenario makes three numbered certificates, optionally with
// two routed certificates followed by a cleaning certificate.
func (w *World) NewCleaningScenario(mixed bool, opts CleaningOptions) (*AuditScenario, error) {
	sc := &AuditScenario{Log: w.NewAuditLog()}
	at := opts.IssuedAt
	if at.IsZero() {
		at = CorpusCutover.Add(45 * time.Hour)
	}
	for i := 0; i < 3; i++ {
		o := CertOptions{ConversationID: ConvD, CustomerID: Customer, IssuedAt: at.Add(time.Duration(i) * time.Minute), Bound: true, Audit: sc.Log, Cleaning: &opts}
		if mixed && i < 2 {
			o.Cleaning = nil
		}
		c, err := w.NewCert(o)
		if err != nil {
			return nil, err
		}
		sc.Certs = append(sc.Certs, c)
	}
	sc.BeforeR2 = sc.Log.Evidence(ConvD)
	if _, err := sc.Log.Publish(at.Add(time.Hour)); err != nil {
		return nil, err
	}
	sc.Evidence = sc.Log.Evidence(ConvD)
	sc.Clean = Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: sc.Certs, Audit: sc.Evidence})
	return sc, nil
}

// Appended last: all existing corpus cases and their expectations stay intact.
func addCleaningCases(co *Corpus) error {
	w := co.World
	sc, err := w.NewCleaningScenario(false, CleaningOptions{})
	if err != nil {
		return err
	}
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
		co.Cases = append(co.Cases, Case{Name: "Cleaning-" + name, What: what, Expect: expect, Step: step, Detail: detail, Zip: f.Zip(), Flags: flags})
	}
	add("00-three", "three anchored cleaning steps without audit claims", ExpectValid, "", "", sc.Clean)
	add("00-three-online", "three cleaning steps with online Rekor confirmation", ExpectValid, "", "", sc.Clean, "--online", "--rekor-url", RekorURLPlaceholder)
	ev, pr := bundle.PathAuditEvents, bundle.PathAuditProofs
	{
		f := sc.Clean.Clone()
		f.EditList(ev, dropSeq(2))
		f.EditList(pr, dropSeq(2))
		f.RemoveCert(sc.Certs[1])
		add("01-middle-removed", "middle certificate and entry removed, manifest re-digested", ExpectTampered, bundle.StepAuditContinuity, "seq gap at 2", f)
	}
	for _, rehash := range []bool{false, true} {
		f := sc.Clean.Clone()
		f.EditList(ev, each(1, func(o map[string]any) {
			o["event_type"] = "PROXY_INFERENCE_COMPLETED"
			if rehash {
				rehashEvent(o)
			}
		}))
		f.Rehash()
		if rehash {
			add("02-type-rehashed", "event type changed and hash recomputed", ExpectTampered, bundle.StepAuditInclusion, "does not lead", f)
		} else {
			add("02-type-changed", "event type changed without changing its hash", ExpectTampered, bundle.StepAuditEventHash, "does not recompute", f)
		}
	}
	for _, rehash := range []bool{false, true} {
		f := sc.Clean.Clone()
		f.EditList(ev, func(l []any) []any {
			a, b := l[0].(map[string]any), l[1].(map[string]any)
			a["request_id"], b["request_id"] = b["request_id"], a["request_id"]
			if rehash {
				rehashEvent(a)
				rehashEvent(b)
			}
			return l
		})
		f.Rehash()
		if rehash {
			add("03-request-swapped-rehashed", "entries presented under other request ids with hashes recomputed", ExpectTampered, bundle.StepAuditInclusion, "does not lead", f)
		} else {
			add("03-request-swapped", "entries presented under other request ids", ExpectTampered, bundle.StepAuditEventHash, "does not recompute", f)
		}
	}
	{
		f := sc.Clean.Clone()
		for _, p := range bundle.AuditPaths {
			delete(f, p)
		}
		m := f.Manifest()
		m.FormatVersion = bundle.FormatVersion
		f.WriteManifest(m)
		add("04-downgrade", "audit files removed, format changed to 1, manifest re-digested (also the audit-fetch-failure shape)", ExpectIncomplete, bundle.StepAuditCounter, "cleaning step", f)
		add("04-downgrade-allow-unanchored", "same format-1 downgrade with relaxed anchors", ExpectIncomplete, bundle.StepAuditCounter, "cleaning step", f, FlagAllowUnanchored)
	}
	{
		f := sc.Clean.Clone()
		for _, p := range bundle.AuditPaths {
			f.PutList(p, []any{})
		}
		f.Rehash()
		add("05-zero-events", "format 2 with zero recorded events", ExpectIncomplete, bundle.StepAuditCounter, "cleaning step", f)
		add("05-zero-events-allow-unanchored", "zero recorded events with relaxed anchors", ExpectIncomplete, bundle.StepAuditCounter, "cleaning step", f, FlagAllowUnanchored)
	}
	{
		f := Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: sc.Certs, Audit: sc.BeforeR2})
		add("06-no-root", "cleaning entries before any root was published", ExpectIncomplete, bundle.StepAuditInclusion, "cleaning step requires", f)
		add("06-no-root-allow-unanchored", "cleaning entries require a root even with relaxed anchors", ExpectIncomplete, bundle.StepAuditInclusion, "cleaning step requires", f, FlagAllowUnanchored)
	}
	mixed, err := w.NewCleaningScenario(true, CleaningOptions{})
	if err != nil {
		return err
	}
	add("07-mixed", "two routed certificates with audit claims and one cleaning step", ExpectValid, "", "", mixed.Clean)
	{
		f := mixed.Clean.Clone()
		f.EditList(ev, dropSeq(3))
		f.EditList(pr, dropSeq(3))
		f.Rehash()
		add("08-missing-entry", "cleaning certificate without an entry among counted routed certificates", ExpectIncomplete, bundle.StepAuditCounter, "cleaning step", f)
	}
	{
		f := mixed.Clean.Clone()
		p := certPath(mixed.Certs[0])
		var doc map[string]any
		if err := json.Unmarshal(f[p], &doc); err != nil {
			return err
		}
		doc["verification"].(map[string]any)["cert_tier"] = "full_chain"
		doc["claims"] = doc["claims"].([]any)[:1]
		f.PutJSON(p, doc)
		f.Rehash()
		add("09-stripped-full-chain", "full-chain certificate with its audit claim stripped and entry retained", ExpectTampered, "signature", "", f)
	}
	other, empty := ConvE, ""
	for _, tc := range []struct {
		name, step, detail string
		opts               CleaningOptions
		expect             string
	}{
		{"10-gateway-conversation-binding", "binding", "different conversation", CleaningOptions{GatewayConversationID: &other}, ExpectTampered},
		{"11-gateway-no-conversation", bundle.StepAuditCounter, "conversation", CleaningOptions{GatewayConversationID: &empty}, ExpectIncomplete},
		{"12-extra-claim", bundle.StepAuditCounter, "no dsa-audit-signed", CleaningOptions{ExtraClaim: true}, ExpectIncomplete},
		{"13-marker-label-mismatch", "claims", "cert_tier_mismatch", CleaningOptions{OmitMarker: true}, ExpectTampered},
		{"14-anchored-wrong-type", bundle.StepAuditCounter, "no dsa-audit-signed", CleaningOptions{EventType: "PROXY_INFERENCE_COMPLETED"}, ExpectIncomplete},
	} {
		s, err := w.NewCleaningScenario(false, tc.opts)
		if err != nil {
			return err
		}
		add(tc.name, "signed and anchored negative fixture: "+tc.name, tc.expect, tc.step, tc.detail, s.Clean)
	}
	// A valid full-chain certificate without an audit claim, beside a genuine
	// anchored seal event: missing linkage is INCOMPLETE, not altered evidence.
	{
		at := CorpusCutover.Add(47 * time.Hour)
		c, err := w.NewCert(CertOptions{ConversationID: ConvD, CustomerID: Customer, IssuedAt: at, Bound: true})
		if err != nil {
			return err
		}
		c.Doc["verification"].(map[string]any)["cert_tier"] = "full_chain"
		if err := c.Remarshal(); err != nil {
			return err
		}
		log := w.NewAuditLog()
		e := syntheticEvent(ConvD, c.RequestID, Customer)
		e.EventType = "SENSITIVE_MODE_CERT_SEALED"
		log.record(e)
		if _, err := log.Publish(at.Add(time.Hour)); err != nil {
			return err
		}
		f := Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: []*Cert{c}, Audit: log.Evidence(ConvD)})
		add("15-full-chain-seal", "valid full-chain certificate without an audit claim beside an anchored seal entry", ExpectIncomplete, bundle.StepAuditCounter, "no dsa-audit-signed", f)
	}
	// PARTIAL is a sealed verdict, not a failure of the strict tier/topology
	// rule. This control is accepted with its anchored entry. Legacy anchors
	// predate the binding cutover and remain valid under --require-anchors.
	{
		at := CorpusCutover.Add(-2 * time.Hour)
		log := w.NewAuditLog()
		c, err := w.NewCert(CertOptions{ConversationID: ConvD, CustomerID: Customer, IssuedAt: at,
			Audit: log, Cleaning: &CleaningOptions{SealedPartial: true}})
		if err != nil {
			return err
		}
		if _, err := log.Publish(at.Add(time.Hour)); err != nil {
			return err
		}
		f := Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: []*Cert{c}, Audit: log.Evidence(ConvD)})
		add("16-partial-with-entry", "sealed PARTIAL with consistent two-signer tier and anchored entry", ExpectValid, "", "", f)
		downgrade := func(f Files) Files {
			f = f.Clone()
			for _, p := range bundle.AuditPaths {
				delete(f, p)
			}
			m := f.Manifest()
			m.FormatVersion = bundle.FormatVersion
			f.WriteManifest(m)
			return f
		}
		add("17-partial-downgrade", "same PARTIAL certificate without audit files", ExpectIncomplete, bundle.StepAuditCounter, "cleaning step", downgrade(f))
		// Change ONLY the unsigned label; certificate signatures and anchors
		// are byte-for-byte identical to the control.
		c.Doc["verification"].(map[string]any)["cert_tier"] = "full_chain"
		if err := c.Remarshal(); err != nil {
			return err
		}
		f[certPath(c)] = c.JSON
		f.Rehash()
		add("18-partial-relabelled-with-entry", "signed facts require an entry but inconsistent SignedCertTier prevents acceptance", ExpectIncomplete, bundle.StepAuditCounter, "no dsa-audit-signed", f)
		add("19-partial-relabelled-downgrade", "unsigned label changed to full_chain, no audit files, required legacy anchors", ExpectIncomplete, bundle.StepAuditCounter, "input-shield certificate", downgrade(f))
		add("19-partial-relabelled-downgrade-allow-unanchored", "same unsigned-label exploit with relaxed anchors", ExpectIncomplete, bundle.StepAuditCounter, "input-shield certificate", downgrade(f), FlagAllowUnanchored)
	}
	{
		// Unlike Cleaning-13, this historical marker-less shape passes the
		// existing chain tier check. Its missing audit linkage stays INCOMPLETE.
		s, err := w.NewCleaningScenario(false, CleaningOptions{OmitMarker: true, UnsignedTier: "full_chain"})
		if err != nil {
			return err
		}
		add("20-historical-compatible", "marker-less two-signer topology with chain-compatible full_chain label", ExpectIncomplete, bundle.StepAuditCounter, "no dsa-audit-signed", s.Clean)
		f := Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: s.Certs})
		add("21-historical-downgrade", "verified topology requires an entry even without a signed marker", ExpectIncomplete, bundle.StepAuditCounter, "input-shield certificate", f)
	}
	{
		s, err := w.NewCleaningScenario(false, CleaningOptions{ExtraClaim: true})
		if err != nil {
			return err
		}
		f := Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: s.Certs})
		add("22-extra-claim-downgrade", "signed marker requires an entry despite ineligible extra-claim topology", ExpectIncomplete, bundle.StepAuditCounter, "input-shield certificate", f)
	}
	// Before-start fixtures use the synthetic override. Existing cases,
	// including the legacy-anchor controls, stay after-start.
	before, err := w.NewCleaningScenario(false, CleaningOptions{IssuedAt: CorpusCleaningStart.Add(-time.Hour)})
	if err != nil {
		return err
	}
	oneBefore := Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: before.Certs[:1]})
	add("23-before-no-entry", "before-start format 1 preserves the released result", ExpectValid, "", "", oneBefore)
	add("24-before-with-entry", "before-start entries are still counted and verified", ExpectValid, "", "", before.Clean)
	bad := before.Clean.Clone()
	bad.EditList(ev, each(1, func(o map[string]any) { o["event_type"] = "PROXY_INFERENCE_COMPLETED" }))
	bad.Rehash()
	add("25-before-tampered-entry", "before-start evidence is never ignored", ExpectTampered, bundle.StepAuditEventHash, "does not recompute", bad)
	{
		log := w.NewAuditLog()
		certs := []*Cert{before.Certs[0]}
		for i := 0; i < 2; i++ {
			c, err := w.NewCert(CertOptions{ConversationID: ConvD, CustomerID: Customer, IssuedAt: CorpusCleaningStart.Add(time.Duration(i) * time.Minute), Bound: true, Audit: log, Cleaning: &CleaningOptions{}})
			if err != nil {
				return err
			}
			certs = append(certs, c)
		}
		if _, err := log.Publish(CorpusCleaningStart.Add(time.Hour)); err != nil {
			return err
		}
		f := Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: certs, Audit: log.Evidence(ConvD)})
		add("26-before-and-after", "one unnumbered before-start certificate and two numbered from the start", ExpectValid, "", "", f)
	}
	{
		c, err := w.NewCert(CertOptions{ConversationID: ConvD, CustomerID: Customer, IssuedAt: CorpusCleaningStart, Bound: true, Cleaning: &CleaningOptions{}})
		if err != nil {
			return err
		}
		f := Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: []*Cert{c}})
		add("27-at-start-no-entry", "the exact signed start instant requires an entry", ExpectIncomplete, bundle.StepAuditCounter, "cleaning step", f)
		c, err = w.NewCert(CertOptions{ConversationID: ConvD, CustomerID: Customer, IssuedAt: CorpusCleaningStart.Add(time.Minute), Bound: true, Cleaning: &CleaningOptions{}})
		if err != nil {
			return err
		}
		c.Doc["created_at"] = CorpusCleaningStart.Add(-time.Hour).Format(time.RFC3339)
		c.Doc["verification"].(map[string]any)["issued_at"] = c.Doc["created_at"]
		if err := c.Remarshal(); err != nil {
			return err
		}
		f = Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: []*Cert{c}})
		m := f.Manifest()
		m.GeneratedAt = c.Doc["created_at"].(string)
		f.WriteManifest(m)
		add("28-unsigned-earlier-date", "unsigned earlier dates cannot move signed issued_at before the start", ExpectIncomplete, bundle.StepAuditCounter, "cleaning step", f)
	}
	{
		historical, err := w.NewCleaningScenario(false, CleaningOptions{IssuedAt: CorpusCleaningStart.Add(-time.Hour), OmitMarker: true, UnsignedTier: "full_chain"})
		if err != nil {
			return err
		}
		f := Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: historical.Certs})
		add("29-before-historical", "before-start marker-less topology preserves the released format-1 result", ExpectValid, "", "", f)
	}
	for _, tc := range []struct {
		name   string
		seq    any
		detail string
	}{
		{"30-counted-entry-removed", json.Number("1"), "entry was removed"},
		{"31-malformed-entry-removed", json.Number("0"), "not a positive integer"},
	} {
		c, err := w.NewCert(CertOptions{ConversationID: ConvD, CustomerID: Customer, IssuedAt: CorpusCutover.Add(time.Hour), Bound: true, Cleaning: &CleaningOptions{AuditSeq: tc.seq, SealedPartial: true, UnsignedTier: "full_chain"}})
		if err != nil {
			return err
		}
		f := Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: []*Cert{c}, Audit: w.NewAuditLog().Evidence(ConvD)})
		add(tc.name, "signed input-shield marker plus audit claim, no entry", ExpectTampered, bundle.StepAuditCounter, tc.detail, f)
	}
	for _, svc := range []string{"dsa-gateway", "dsa-sanitizer", "dsa-bridge"} {
		c, err := w.NewCert(CertOptions{ConversationID: ConvD, CustomerID: Customer, IssuedAt: CorpusCutover.Add(time.Hour), Bound: true, Cleaning: &CleaningOptions{OmitMarker: true, DuplicateService: svc, UnsignedTier: "full_chain"}})
		if err != nil {
			return err
		}
		f := Build(Spec{ConversationID: ConvD, CustomerID: Customer, Certs: []*Cert{c}})
		add("32-marker-less-extra-"+svc, "marker-less topology with an extra signed service claim", ExpectIncomplete, bundle.StepAuditCounter, "this input-shield certificate has no counter entry", f)
	}
	return nil
}
