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
	at := CorpusCutover.Add(45 * time.Hour)
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
			add("02-type-rehashed", "event type changed and hash recomputed", ExpectTampered, bundle.StepAuditCounter, "event type", f)
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
		{"10-gateway-conversation", bundle.StepAuditCounter, "conversation", CleaningOptions{GatewayConversationID: &other}, ExpectTampered},
		{"11-gateway-no-conversation", bundle.StepAuditCounter, "conversation", CleaningOptions{GatewayConversationID: &empty}, ExpectIncomplete},
		{"12-extra-claim", bundle.StepAuditCounter, "two-signer", CleaningOptions{ExtraClaim: true}, ExpectTampered},
		{"13-no-signed-marker", "claims", "cert_tier_mismatch", CleaningOptions{OmitMarker: true}, ExpectTampered},
		{"14-anchored-wrong-type", bundle.StepAuditCounter, "event type", CleaningOptions{EventType: "PROXY_INFERENCE_COMPLETED"}, ExpectTampered},
	} {
		s, err := w.NewCleaningScenario(false, tc.opts)
		if err != nil {
			return err
		}
		add(tc.name, "signed and anchored negative fixture: "+tc.name, tc.expect, tc.step, tc.detail, s.Clean)
	}
	// A valid full-chain certificate without an audit claim, beside a genuine
	// anchored seal event: rejection must come from the tier gate itself.
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
		add("15-full-chain-seal", "valid full-chain certificate without an audit claim beside an anchored seal entry", ExpectTampered, bundle.StepAuditCounter, "two-signer", f)
	}
	return nil
}
