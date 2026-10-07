package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/anchor"
)

// Step names of the audit checks (design §5.3, checks A–J).
const (
	StepAuditFiles        = "audit-files"      // shape of audit/*.json and the references between them
	StepAuditConversation = "audit-binding"    // C
	StepAuditEventHash    = "audit-event-hash" // B
	StepAuditContinuity   = "audit-continuity" // D
	StepAuditRoot         = "audit-root"       // G (J when there is none)
	StepAuditCounter      = "audit-counter"    // A, I (per certificate)
	StepAuditInclusion    = "audit-inclusion"  // F, H, J (per counted request)
	StepAuditCertificates = "audit-certs"      // E
	cleaningEventType     = "SENSITIVE_MODE_CERT_SEALED"
)

// auditVerifier runs the counter and inclusion checks of a format-2 bundle.
type auditVerifier struct {
	r   *Report
	m   *Manifest
	opt Options
	// d is nil when the audit files did not parse (audit-files FAILED); the
	// per-certificate steps then stay silent.
	d     *auditData
	byReq map[string]*AuditEvent
	// rootOK holds the roots that verified (signature + Rekor), by root id.
	// A tree size is only ever read from here: the signed, anchored artifact.
	rootOK map[uint64]*anchor.AuditRootResult
	// anchored: the bundle carries a root, a proof or a row that names a root.
	anchored bool
	certSeen map[string]bool
}

// newAuditVerifier parses audit/ and runs the bundle-level checks that need
// no certificate: B (event hashes), C (conversation), D (continuity) and G
// (root anchors).
func newAuditVerifier(r *Report, m *Manifest, files map[string][]byte, opt Options) *auditVerifier {
	a := &auditVerifier{r: r, m: m, opt: opt, byReq: map[string]*AuditEvent{}, rootOK: map[uint64]*anchor.AuditRootResult{}, certSeen: map[string]bool{}}
	d, refProblems, err := parseAudit(files)
	if err != nil {
		r.add("bundle", StepAuditFiles, Fail, short(err.Error()))
		return a
	}
	a.d = d
	r.AuditEvents = len(d.events)
	if len(refProblems) > 0 {
		r.add("bundle", StepAuditFiles, Fail, short(strings.Join(refProblems, "; ")))
	} else {
		r.add("bundle", StepAuditFiles, Pass, fmt.Sprintf("%d counted request(s), %d inclusion proof(s), %d audit root(s)", len(d.events), len(d.proofs), len(d.roots)))
	}
	a.anchored = len(d.roots) > 0
	for _, p := range d.proofs {
		a.anchored = a.anchored || !p.noProof()
	}
	for i := range d.events {
		e := &d.events[i]
		a.anchored = a.anchored || e.Anchored()
		if e.RequestID != "" {
			a.byReq[e.RequestID] = e
		}
	}
	a.conversation()
	a.eventHashes()
	a.continuity()
	a.roots()
	return a
}

// conversation is check C: every counter entry names the bundle's
// conversation (the manifest id, which the signed claims of every
// certificate are checked against in the binding step).
func (a *auditVerifier) conversation() {
	for _, e := range a.d.events {
		if e.ConversationID != a.m.ConversationID {
			a.r.add("bundle", StepAuditConversation, Fail, fmt.Sprintf("counter entry seq %d names another conversation than this bundle", e.ConvSeq))
			return
		}
	}
	if len(a.d.events) == 0 {
		a.r.skip("bundle", StepAuditConversation, "no counted request in this bundle", false)
		return
	}
	a.r.add("bundle", StepAuditConversation, Pass, "every counter entry names this bundle's conversation")
}

// eventHashes is check B: each entry's event_hash recomputes from its own
// fields under the v2 serialisation, so conversation_id and conv_seq are
// inside the hash the audit service signed.
func (a *auditVerifier) eventHashes() {
	var bad []string
	for _, e := range a.d.events {
		if EventHashV2(e) != e.EventHash {
			bad = append(bad, fmt.Sprintf("%d", e.ConvSeq))
		}
	}
	switch {
	case len(bad) > 0:
		a.r.add("bundle", StepAuditEventHash, Fail, "the event_hash of counter entry seq "+short(strings.Join(bad, ", "))+
			" does not recompute from its fields (conversation, seq, request, event or payload digest altered)")
	case len(a.d.events) == 0:
		a.r.skip("bundle", StepAuditEventHash, "no counted request in this bundle", false)
	default:
		a.r.add("bundle", StepAuditEventHash, Pass, fmt.Sprintf("%d of %d event hashes recompute (v2 serialisation: conversation and seq are inside the hash)", len(a.d.events), len(a.d.events)))
	}
}

// continuity is check D: the conv_seq values are exactly 1…N.
func (a *auditVerifier) continuity() {
	n := uint64(len(a.d.events))
	if n == 0 {
		a.r.skip("bundle", StepAuditContinuity, "no counted request in this bundle", false)
		return
	}
	seen := map[uint64]bool{}
	for _, e := range a.d.events {
		if seen[e.ConvSeq] {
			a.r.add("bundle", StepAuditContinuity, Fail, fmt.Sprintf("duplicate seq %d: two counter entries carry the same number", e.ConvSeq))
			return
		}
		seen[e.ConvSeq] = true
	}
	// n distinct positive numbers are 1…n exactly when none of 1…n is missing.
	for k := uint64(1); k <= n; k++ {
		if !seen[k] {
			a.r.add("bundle", StepAuditContinuity, Fail, fmt.Sprintf("seq gap at %d: the counter entries do not run 1..N without a hole (a counted request is missing)", k))
			return
		}
	}
	for i, e := range a.d.events {
		if e.ConvSeq != uint64(i)+1 {
			a.r.add("bundle", StepAuditContinuity, Fail, fmt.Sprintf("counter entries are not listed in seq order (position %d holds seq %d)", i+1, e.ConvSeq))
			return
		}
	}
	a.r.add("bundle", StepAuditContinuity, Pass, fmt.Sprintf("seq 1..%d, no gap, no duplicate", n))
}

// roots is check G for every root in the bundle (J when there is none).
func (a *auditVerifier) roots() {
	r := a.r
	if len(a.d.roots) == 0 {
		r.skip("bundle", StepAuditRoot, "not anchored: the bundle carries no audit root", false)
		return
	}
	key := a.opt.Roots.ServiceKeys[anchor.AuditRootSigner]
	for _, rt := range a.d.roots {
		label := fmt.Sprintf("root %d (tree size %d)", rt.ID, rt.TreeSize)
		if len(key) != ed25519.PublicKeySize {
			r.skip("bundle", StepAuditRoot, label+": "+errNoAuditKey.Error(), true)
			continue
		}
		entry := rt.Root.Entry
		if a.opt.Fetcher != nil {
			var err error
			entry, err = confirmOnline(a.opt.Fetcher, a.opt.Roots.Rekor, entry, key, anchor.AuditRootSigner)
			if err != nil {
				r.add("bundle", StepAuditRoot, Fail, label+": "+short(err.Error()))
				continue
			}
		}
		res, err := anchor.VerifyAuditRoot(anchor.AuditRoot{Artifact: rt.Root.Artifact, Signature: rt.Root.Signature, Entry: entry}, a.opt.Roots.Rekor, key)
		if errors.Is(err, anchor.ErrRekorNoBody) {
			r.add("bundle", StepAuditRoot, Fail, label+": the root's Rekor entry carries no body or integrated time")
			continue
		}
		if err != nil {
			r.add("bundle", StepAuditRoot, Fail, label+": "+short(err.Error()))
			continue
		}
		if res.TreeSize != rt.TreeSize || hex.EncodeToString(res.Root) != rt.RootHash {
			r.add("bundle", StepAuditRoot, Fail, fmt.Sprintf("%s: the tree_size / root_hash fields differ from the signed root artifact (which says tree size %d)", label, res.TreeSize))
			continue
		}
		a.rootOK[rt.ID] = res
		mode := "stored entry"
		if a.opt.Fetcher != nil {
			mode = "stored entry, confirmed by the log's current copy"
		}
		r.add("bundle", StepAuditRoot, Pass, fmt.Sprintf("%s, root hash %s...: signed by the pinned %s key; Rekor log index %d, integrated %s; SET + inclusion proof + signed checkpoint verified; entry made by the %s key for this root artifact (%s)",
			label, rt.RootHash[:16], anchor.AuditRootSigner, res.LogIndex, res.IntegratedTime.Format(time.RFC3339), anchor.AuditRootSigner, mode))
	}
	r.AuditRoots = len(a.rootOK)
}

// inclusion is checks F, H and J for one counter entry. issuedAt is the
// signed issued_at of the request's certificate (zero if unknown).
//
// The tree size and the root come ONLY from the root's signed artifact, and
// only after its signature and Rekor entry verified (rootOK). An inclusion
// path does not pin the tree size — several sizes share one path shape — so
// the proof's own tree_size (and the root entry's tree_size field, checked in
// roots) is an unsigned copy that must equal the signed value and is never
// used in its place.
func (a *auditVerifier) inclusion(e *AuditEvent, issuedAt time.Time) (Status, string, bool) {
	if !e.Anchored() {
		when := "in about an hour"
		if !issuedAt.IsZero() {
			when = "after " + issuedAt.UTC().Truncate(time.Hour).Add(time.Hour).Format("2006-01-02T15:04Z")
		}
		switch {
		case a.anchored:
			return Skipped, "not yet anchored: this request is newer than the latest anchored audit root. A root covering new audit rows is published hourly; export the bundle again " + when, true
		case a.opt.Roots.RequireAnchors:
			return Skipped, "not anchored: the bundle carries no audit root, and under these trust roots every counted request must be anchored. A root covering new audit rows is published hourly: export the bundle again " +
				when + " (for a self-hosted deployment without anchoring pass --allow-unanchored)", true
		}
		return Skipped, "not anchored: this bundle carries no audit root", false
	}
	rt := a.d.byID[e.RootRef]
	p, hasProof := a.d.proofs[e.ConvSeq]
	if rt == nil || !hasProof || p.noProof() {
		return Fail, "the inclusion proof or the root it names is missing (see audit-files)", false
	}
	res := a.rootOK[rt.ID]
	if res == nil {
		return Skipped, fmt.Sprintf("audit root %d did not verify (see audit-root), so there is no signed tree size and root to check this request's inclusion proof against", rt.ID), true
	}
	if p.TreeSize != res.TreeSize {
		return Fail, fmt.Sprintf("the inclusion proof claims tree size %d, the signed root artifact of root %d says %d", p.TreeSize, rt.ID, res.TreeSize), false
	}
	if p.LeafIndex != e.LeafIndex {
		return Fail, fmt.Sprintf("the inclusion proof is for leaf %d, the counter entry says leaf %d", p.LeafIndex, e.LeafIndex), false
	}
	got, err := anchor.AuditInclusionRoot(e.LeafIndex, res.TreeSize, e.EventHash, p.Path)
	if err != nil {
		return Fail, short(err.Error()), false
	}
	if !bytes.Equal(got, res.Root) {
		return Fail, fmt.Sprintf("the inclusion proof does not lead from this request's event_hash (leaf %d) to the signed audit root of tree size %d", e.LeafIndex, res.TreeSize), false
	}
	return Pass, fmt.Sprintf("leaf %d of the audit log at tree size %d (size and root from the signed artifact of root %d); that root was logged in Rekor at %s (log index %d), so this row existed by then",
		e.LeafIndex, res.TreeSize, rt.ID, res.IntegratedTime.Format(time.RFC3339), res.LogIndex), false
}

func (a *auditVerifier) emit(scope, name string, st Status, detail string, blocks bool) {
	if st == Skipped {
		a.r.skip(scope, name, detail, blocks)
		return
	}
	a.r.add(scope, name, st, detail)
}

// cert runs checks A and I and the inclusion check for one certificate.
// scope is the certificate's request id; issuedAt its SIGNED issued_at (zero
// when the witness signature did not verify).
func (a *auditVerifier) cert(scope string, ca certAudit, issuedAt time.Time) {
	a.certSeen[scope] = true
	if a.d == nil {
		return
	}
	r := a.r
	e := a.byReq[scope]
	if e == nil {
		noCounterEntry(r, scope, ca, true)
		return
	}
	cleaningMatched := false
	switch {
	case !ca.claimsVerified:
		r.skip(scope, StepAuditCounter, fmt.Sprintf("this certificate's claim signatures were not verified, so its counter entry (seq %d) is not tied to it", e.ConvSeq), true)
	case ca.cleaningStepEligible && e.EventType == cleaningEventType:
		// The only claim-less exception: authenticated two-claim tier,
		// request id (byReq), seal event type and signed gateway conversation.
		// Inclusion below remains mandatory, even with --allow-unanchored.
		switch {
		case ca.gatewayConversationID == "":
			r.skip(scope, StepAuditCounter, "the cleaning step's verified gateway claim carries no conversation id", true)
		case e.ConversationID != ca.gatewayConversationID:
			r.add(scope, StepAuditCounter, Fail, "the counter entry's conversation id differs from the cleaning step's verified gateway claim")
		default:
			cleaningMatched = true
			r.add(scope, StepAuditCounter, Pass, fmt.Sprintf("seq %d (of %d counted in this bundle): cleaning step with the signed two-signer tier and matching gateway conversation; certificate-to-number linkage requires the anchored audit entry", e.ConvSeq, len(a.d.events)))
		}
	case len(ca.claims) == 0:
		r.skip(scope, StepAuditCounter, fmt.Sprintf("this certificate carries no %s-signed %s claim, so its counter entry (seq %d) is not tied to it by a signature", AuditClaimService, AuditClaimType, e.ConvSeq), true)
	default:
		st, detail := matchAuditClaim(ca.claims, e, len(a.d.events))
		// Audit-claim matching cannot waive the independent signed-fact
		// requirement for a strictly accepted cleaning entry. Ineligibility
		// establishes missing linkage, never contradictory evidence.
		if ca.needsCleaningEntry && st == Pass {
			st, detail = Skipped, "a SENSITIVE_MODE_CERT_SEALED entry requires the signed two-signer input-shield tier with exactly one gateway and one sanitizer claim"
		}
		// A SKIPPED counter step always blocks: the entry is not tied to the
		// certificate, so the bundle is not complete.
		a.emit(scope, StepAuditCounter, st, detail, true)
	}
	st, detail, blocks := a.inclusion(e, issuedAt)
	if ca.needsCleaningEntry && !e.Anchored() {
		st, detail, blocks = Skipped, "a cleaning step requires inclusion under an anchored audit root, including with --allow-unanchored; export the bundle again after its root is published", true
	}
	a.emit(scope, StepAuditInclusion, st, detail, blocks)
	if cleaningMatched && st == Pass {
		// Count accepted entries even when an unrelated certificate or an
		// incomplete exporter listing blocks the bundle's overall result.
		// This entry's root passed inclusion; the shared audit checks and all
		// checks of this certificate must also have passed.
		for _, s := range r.Steps {
			shared := s.Scope == "bundle" && (s.Name == StepAuditFiles || s.Name == StepAuditConversation || s.Name == StepAuditEventHash || s.Name == StepAuditContinuity)
			if (shared || s.Scope == scope) && (s.Status == Fail || s.Incomplete) {
				return
			}
		}
		r.CleaningSteps++
	}
}

// matchAuditClaim is check A for a certificate whose request HAS a counter
// entry e (found by request id; there is at most one entry per request).
//
// Outside the cleaning-step exception above, counting is what the audit-signed claim says: the
// audit service puts conversation_id + conv_seq into the EVENTS_RECORDED
// claim of every counted request (design D3) and into no other. So:
//
//   - EVERY claim that signs a counter must be this entry: same request id,
//     event_hash, conversation and number. A claim that signs a number the
//     bundle has no entry for is TAMPERED, also when another claim of the
//     same certificate matches (two claims signing seq 1 and seq 2 with one
//     entry: FAIL);
//   - no claim signs a counter, and none names the entry's event_hash ->
//     TAMPERED: the entry asserts a number for this request that no signature
//     of the certificate covers;
//   - no claim signs a counter, but one names the entry's event_hash -> "not
//     tracked", SKIPPED and blocking (INCOMPLETE): the certificate itself
//     does not say it was counted, so the entry is not accepted on the hash
//     alone and the bundle is not VALID.
//
// PASS therefore always means: a signature states this conversation and this
// number, and no signature of the certificate states another.
func matchAuditClaim(claims []auditClaim, e *AuditEvent, total int) (Status, string) {
	for _, c := range claims {
		if c.seqMalformed {
			return Fail, "the signed audit claim carries a conv_seq that is not a positive integer"
		}
	}
	counted, hashOnly := 0, false
	for i := range claims {
		c := &claims[i]
		if !c.hasSeq {
			hashOnly = hashOnly || (c.eventHash == e.EventHash && e.EventHash != "")
			continue
		}
		counted++
		if c.eventHash != e.EventHash || e.EventHash == "" {
			return Fail, fmt.Sprintf("the %s-signed %s claim of this certificate states it was counted as seq %d with event_hash %s, the counter entry for this request is seq %d with event_hash %s",
				AuditClaimService, AuditClaimType, c.seq, quotedShort(c.eventHash), e.ConvSeq, quotedShort(e.EventHash))
		}
		if c.seq != e.ConvSeq {
			return Fail, fmt.Sprintf("the %s-signed %s claim of this certificate states it was counted as seq %d, the counter entry for this request says seq %d (every signed counter claim needs its own counter entry)",
				AuditClaimService, AuditClaimType, c.seq, e.ConvSeq)
		}
		for _, f := range []struct {
			name, signed, entry string
			required            bool
		}{
			{"conversation_id", c.conversationID, e.ConversationID, true},
			{"request_id", c.requestID, e.RequestID, false},
			{"event_id", c.eventID, e.EventID, false}, {"event_type", c.eventType, e.EventType, false}, {"source_service", c.sourceService, e.SourceService, false},
		} {
			if (f.required || f.signed != "") && f.signed != f.entry {
				return Fail, fmt.Sprintf("the signed audit claim (seq %d) states %s %s, the counter entry says %s", c.seq, f.name, quotedShort(f.signed), quotedShort(f.entry))
			}
		}
	}
	switch {
	case counted > 0:
		return Pass, fmt.Sprintf("seq %d (of %d counted in this bundle): the %s-signed %s claim names this entry's event_hash and itself signs this conversation and seq",
			e.ConvSeq, total, AuditClaimService, AuditClaimType)
	case hashOnly:
		return Skipped, fmt.Sprintf("not tracked: the %s-signed %s claim of this certificate carries no counter (no conversation_id + conv_seq), although the bundle lists a counter entry (seq %d) with its event_hash. The claim of a counted request always signs its number, so this entry is not accepted for this certificate",
			AuditClaimService, AuditClaimType, e.ConvSeq)
	}
	return Fail, fmt.Sprintf("the %s-signed %s claim of this certificate names event_hash %s and carries no counter, the counter entry for this request (seq %d) has %s: the entry asserts a number that no signature of this certificate covers",
		AuditClaimService, AuditClaimType, quotedShort(claims[0].eventHash), e.ConvSeq, quotedShort(e.EventHash))
}

// noCounterEntry reports a certificate whose request has no counter entry
// (check I and the downgrade guard).
//
// Cleaning steps always need an anchored matching entry. Its absence is
// INCOMPLETE in either format: the audit record may never have been written.
//
// Whether a request was counted is stated by a signature: the audit service
// puts conversation_id + conv_seq into the EVENTS_RECORDED claim of every
// counted request (design D3) and into no other. So:
//
//   - a claim signs a seq and a format-2 bundle has no entry for it ->
//     TAMPERED: the entry was removed (every signed counter claim needs its
//     entry);
//   - the claim signs a seq and the bundle is format 1 (no audit/ folder: a
//     format-2 bundle downgraded, or an export that could not fetch the
//     counter) -> INCOMPLETE: such a bundle must not pass as complete;
//   - the claim signs no counter -> "not tracked" (recorded before counting
//     started, or by a gateway that sent no conversation id) -> INCOMPLETE,
//     never TAMPERED. No date compiled into the tool is involved, so a
//     gateway rollback cannot turn honest certificates into forgeries.
//
// inAuditBundle is false for a format-1 bundle, where a step is emitted only
// for cleaning steps or the second case (otherwise output is unchanged).
func noCounterEntry(r *Report, scope string, ca certAudit, inAuditBundle bool) {
	seq, counted := ca.countedSeq()
	malformed := false
	for _, c := range ca.claims {
		malformed = malformed || c.seqMalformed
	}
	switch {
	case ca.needsCleaningEntry:
		r.skip(scope, StepAuditCounter, "this cleaning step has no counter entry; an anchored matching entry is required in every bundle format, including with --allow-unanchored", true)
	case !inAuditBundle && counted:
		r.skip(scope, StepAuditCounter, fmt.Sprintf("the %s-signed claim of this certificate states its request was counted (seq %d), but this is a format-1 bundle without the audit counter (a format-2 bundle with its audit/ folder removed, or an export that could not fetch the counter): export the bundle again",
			AuditClaimService, seq), true)
	case !inAuditBundle:
		// Format 1 and nothing signed says "counted": output unchanged.
	case counted:
		r.add(scope, StepAuditCounter, Fail, fmt.Sprintf("the %s-signed %s claim of this certificate states its request was counted as seq %d, but the bundle has no counter entry for it (the entry was removed)",
			AuditClaimService, AuditClaimType, seq))
	case malformed:
		r.add(scope, StepAuditCounter, Fail, "the signed audit claim carries a conv_seq that is not a positive integer")
	case !ca.claimsVerified:
		r.skip(scope, StepAuditCounter, "request has no counter entry, and this certificate's claim signatures were not verified, so whether it was counted is not known", true)
	case len(ca.claims) == 0:
		r.skip(scope, StepAuditCounter, fmt.Sprintf("request has no counter entry, and this certificate carries no %s-signed %s claim that would say whether it was counted", AuditClaimService, AuditClaimType), true)
	default:
		r.skip(scope, StepAuditCounter, "not tracked: request has no counter entry, and its signed audit claim carries no counter (recorded before counting started, or sent without a conversation id)", true)
	}
}

// finish is check E plus the inclusion check of every counted request that
// has no certificate in the bundle.
func (a *auditVerifier) finish() {
	if a.d == nil {
		return
	}
	r := a.r
	var missing []string
	for i := range a.d.events {
		e := &a.d.events[i]
		if a.certSeen[e.RequestID] {
			continue
		}
		missing = append(missing, fmt.Sprintf("request seq %d has no certificate (request_id %s)", e.ConvSeq, quotedShort(e.RequestID)))
		st, detail, blocks := a.inclusion(e, time.Time{})
		a.emit("bundle", StepAuditInclusion, st, fmt.Sprintf("seq %d (no certificate): %s", e.ConvSeq, detail), blocks)
	}
	switch {
	case len(missing) > 0:
		more := ""
		if len(missing) > 8 {
			more = fmt.Sprintf("; and %d more", len(missing)-8)
			missing = missing[:8]
		}
		r.skip("bundle", StepAuditCertificates, strings.Join(missing, "; ")+more+
			": the audit log counted the request, the bundle holds no certificate for it (removed from the bundle, or the witness never sealed one)", true)
	case len(a.d.events) == 0:
		r.skip("bundle", StepAuditCertificates, "no counted request in this bundle", false)
	default:
		r.add("bundle", StepAuditCertificates, Pass, fmt.Sprintf("each of the %d counted requests has its certificate in the bundle", len(a.d.events)))
	}
}

// confirmOnline re-fetches an entry from the log. The log's copy CONFIRMS the
// stored entry and never replaces it: the stored SET and the stored inclusion
// proof are still the ones verified (by the caller). Only a legacy entry that
// never stored its body / integrated time gets those two values from the log
// — and they must then match the STORED SET. The log's own copy must verify
// too (SET, proof, checkpoint, and that the pinned key made the entry).
func confirmOnline(f RekorFetcher, rk *anchor.RekorKey, stored anchor.RekorEntry, key ed25519.PublicKey, signer string) (anchor.RekorEntry, error) {
	fe, err := f.Fetch(stored.LogIndex)
	if err != nil {
		return stored, fmt.Errorf("online re-fetch of log index %d failed: %w", stored.LogIndex, err)
	}
	if fe.LogIndex != stored.LogIndex {
		return stored, errors.New("the log returned a different index")
	}
	if len(stored.CanonicalBody) > 0 && !bytes.Equal(stored.CanonicalBody, fe.Body) {
		return stored, errors.New("the stored entry body differs from the log's entry at this index")
	}
	if stored.IntegratedTime != 0 && stored.IntegratedTime != fe.IntegratedTime {
		return stored, errors.New("the stored integrated time differs from the log's")
	}
	logCopy := anchor.RekorEntry{LogIndex: fe.LogIndex, InclusionProof: fe.InclusionProof, SignedEntryTimestamp: fe.SignedEntryTimestamp,
		CanonicalBody: fe.Body, IntegratedTime: fe.IntegratedTime}
	if _, err := anchor.VerifyRekorBy(logCopy, rk, key, signer); err != nil {
		return stored, fmt.Errorf("the log's current copy of this entry does not verify: %w", err)
	}
	out := stored
	if len(out.CanonicalBody) == 0 {
		out.CanonicalBody = fe.Body
	}
	if out.IntegratedTime == 0 {
		out.IntegratedTime = fe.IntegratedTime
	}
	return out, nil
}
