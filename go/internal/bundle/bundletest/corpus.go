package bundletest

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/bundle"
)

// Expectation of one corpus case on the built binary.
const (
	ExpectValid    = "VALID(0)"
	ExpectDetected = "DETECTED(1|2)"
	// ExpectKnownGap marks a documented v1 limit: the tool is EXPECTED to
	// exit 0, and the case exists so the limit is measured, not assumed.
	ExpectKnownGap = "KNOWN-GAP(0)"
	// ExpectTampered: the mutation must exit exactly 1 (TAMPERED), not just
	// "not VALID" — for shapes where INCOMPLETE would let an explicit
	// --allow-unanchored turn the forgery VALID (Sol #77 P1).
	ExpectTampered = "TAMPERED(1)"
)

// FlagAllowUnanchored in Case.Flags runs that case under the self-hosted
// no-anchoring policy: the runner drops the corpus's --require-anchors
// (CaseArgs), since the two flags exclude each other.
const FlagAllowUnanchored = "--allow-unanchored"

// CaseArgs is the full argument list for one case: the world's flags
// (minus --require-anchors when the case asks for --allow-unanchored), the
// case's own flags with the Rekor URL filled in, then the zip path.
// tamper-corpus.sh applies the same rule.
func CaseArgs(base, caseFlags []string, rekorURL, zipPath string) []string {
	allow := false
	for _, f := range caseFlags {
		if f == FlagAllowUnanchored {
			allow = true
		}
	}
	out := make([]string, 0, len(base)+len(caseFlags)+1)
	for _, f := range base {
		if allow && f == "--require-anchors" {
			continue
		}
		out = append(out, f)
	}
	out = append(out, ExpandFlags(caseFlags, rekorURL)...)
	return append(out, zipPath)
}

// RekorURLPlaceholder in Case.Flags stands for the base URL of the corpus's
// local fake Rekor server (bundlecorpus -serve).
const RekorURLPlaceholder = "@REKOR_URL@"

// Case is one corpus entry.
type Case struct {
	Name   string
	What   string
	Expect string
	Zip    []byte
	// Flags are extra lucairn-bundle-verify flags for this case only (e.g.
	// --online --rekor-url @REKOR_URL@).
	Flags []string
	// Step and Detail (S2b cases) name the check that must report the
	// mutation: a step of that name that is FAIL or a blocking SKIPPED, whose
	// detail contains Detail. The in-process test asserts it, so each case
	// measures the check it is named for and not an accidental side effect.
	Step, Detail string
}

// Corpus is the synthetic world plus every case.
type Corpus struct {
	World *World
	Cases []Case
	// Clean is the clean bundle's files; Originals are the synthetic
	// "original values" no bundle file may contain.
	Clean Files
	// Entries are the synthetic log's entries for the clean bundle's
	// certificates, by global log index (what --online fetches).
	Entries map[int64]*bundle.FetchedEntry
	// RekorOnly is a binding-v1 certificate whose TSA rail failed (cert_hash
	// + marker kept, no token), for tests under another anchor policy.
	RekorOnly *Cert
	// Audit and AuditSelfHosted are the format-2 scenarios (T-1231 S2b): the
	// hosted one and a self-hosted one without anchoring.
	Audit, AuditSelfHosted *AuditScenario
}

// Fetcher serves Entries in-process (the tests' stand-in for --online).
func (co *Corpus) Fetcher() bundle.RekorFetcher { return entryFetcher(co.Entries) }

type entryFetcher map[int64]*bundle.FetchedEntry

func (e entryFetcher) Fetch(i int64) (*bundle.FetchedEntry, error) {
	if x, ok := e[i]; ok {
		return x, nil
	}
	return nil, fmt.Errorf("no entry %d", i)
}

// EntryOf is the log's copy of c's Rekor entry, as --online fetches it.
func EntryOf(c *Cert) (*bundle.FetchedEntry, error) {
	tl, ok := c.Doc["attestation"].(map[string]any)["transparency_log"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("certificate %s has no Rekor entry", c.RequestID)
	}
	dec := func(k string) []byte {
		b, _ := base64.StdEncoding.DecodeString(tl[k].(string))
		return b
	}
	idx, err := strconv.ParseInt(tl["log_index"].(string), 10, 64)
	if err != nil {
		return nil, err
	}
	it, err := strconv.ParseInt(tl["integrated_time"].(string), 10, 64)
	if err != nil {
		return nil, err
	}
	return &bundle.FetchedEntry{Body: dec("canonical_body"), IntegratedTime: it, LogIndex: idx,
		SignedEntryTimestamp: dec("signed_entry_timestamp"), InclusionProof: dec("inclusion_proof")}, nil
}

const (
	ConvA     = "c0ffee00000000000000000000000a01"
	ConvB     = "c0ffee00000000000000000000000b02"
	ConvC     = "c0ffee00000000000000000000000c03"
	Customer  = "cust_synthetic_alpha"
	Customer2 = "cust_synthetic_beta"
)

// NewCorpus builds the clean bundle and every mutation.
func NewCorpus() (*Corpus, error) {
	w, err := NewWorld("corpus")
	if err != nil {
		return nil, err
	}
	base := time.Date(2026, 9, 28, 9, 0, 0, 0, time.UTC)
	mk := func(conv, cust string, at time.Time) *Cert {
		c, err2 := w.NewCert(CertOptions{ConversationID: conv, CustomerID: cust, IssuedAt: at})
		if err2 != nil {
			err = err2
		}
		return c
	}
	earlier := mk(ConvC, Customer, base.Add(-48*time.Hour))
	a := []*Cert{mk(ConvA, Customer, base), mk(ConvA, Customer, base.Add(40*time.Second)), mk(ConvA, Customer, base.Add(95*time.Second))}
	b := []*Cert{mk(ConvB, Customer, base.Add(30*time.Minute))}
	other := mk(ConvA, Customer2, base.Add(time.Minute))
	later := mk(ConvC, Customer, base.Add(48*time.Hour))
	// T-1231 S2a: certificates of the binding-v1 witness, issued after the
	// synthetic cutover (CorpusCutover), plus edge cases around it. Minted
	// AFTER the S1 certificates so those stay byte-identical.
	mkB := func(conv, cust string, at time.Time) *Cert {
		c, err2 := w.NewCert(CertOptions{ConversationID: conv, CustomerID: cust, IssuedAt: at, Bound: true})
		if err2 != nil {
			err = err2
		}
		return c
	}
	// Must stay in the past: tokens dated in the future FAIL.
	bbase := CorpusCutover.Add(24*time.Hour + 9*time.Hour)
	ab := []*Cert{mkB(ConvA, Customer, bbase), mkB(ConvA, Customer, bbase.Add(40*time.Second)), mkB(ConvA, Customer, bbase.Add(95*time.Second))}
	laterBound := mkB(ConvC, Customer, bbase.Add(48*time.Hour))
	postCutoverUnbound := mk(ConvA, Customer, bbase.Add(3*time.Minute))
	preCutoverBound := mkB(ConvA, Customer, base.Add(2*time.Minute))
	// Fix round (gate "Round-1 verdict S2a"): a binding-v1 certificate whose
	// TSA rail failed — Rekor only, cert_hash + marker kept (D3).
	rekorOnly := mkB(ConvA, Customer, bbase.Add(4*time.Minute))
	if err != nil {
		return nil, err
	}
	clean := Build(Spec{ConversationID: ConvA, CustomerID: Customer, Certs: a})
	co := &Corpus{World: w, Clean: clean, Entries: map[int64]*bundle.FetchedEntry{}}
	for _, c := range a {
		e, err := EntryOf(c)
		if err != nil {
			return nil, err
		}
		co.Entries[e.LogIndex] = e
	}
	addF := func(name, what, expect string, f Files, flags ...string) {
		co.Cases = append(co.Cases, Case{Name: name, What: what, Expect: expect, Zip: f.Zip(), Flags: flags})
	}
	add := func(name, what, expect string, f Files) {
		co.Cases = append(co.Cases, Case{Name: name, What: what, Expect: expect, Zip: f.Zip()})
	}
	online := []string{"--online", "--rekor-url", RekorURLPlaceholder}
	path := func(c *Cert) string { return bundle.DirCertificates + c.RequestID + ".json" }
	edit := func(f Files, c *Cert, fn func(doc map[string]any)) {
		var doc map[string]any
		if err := json.Unmarshal(f[path(c)], &doc); err != nil {
			panic(err)
		}
		fn(doc)
		bts, _ := json.MarshalIndent(doc, "", "  ")
		f[path(c)] = bts
	}
	att := func(doc map[string]any) map[string]any { return doc["attestation"].(map[string]any) }
	swapIn := func(f Files, victim, donor *Cert) {
		delete(f, path(victim))
		f[path(donor)] = donor.JSON
		m := f.Manifest()
		for i := range m.Certificates {
			if m.Certificates[i].RequestID == victim.RequestID {
				m.Certificates[i] = bundle.ManifestCert{Path: path(donor), RequestID: donor.RequestID, CertificateID: donor.CertificateID}
			}
		}
		f.WriteManifest(m)
	}

	add("00-clean", "untouched synthetic bundle (3 certificates, all anchored)", ExpectValid, clean.Clone())
	{
		f := clean.Clone()
		f[bundle.PathReportInternal] = SyntheticPDF
		f.Rehash()
		add("00-clean-with-internal", "clean bundle that also carries report-internal.pdf (listed)", ExpectValid, f)
	}

	// 1. Byte flip in a signed certificate field, manifest re-hashed.
	{
		f := clean.Clone()
		edit(f, a[1], func(d map[string]any) {
			s := d["issued_at"].(string)
			d["issued_at"] = s[:len(s)-2] + "8Z"
		})
		f.Rehash()
		add("01-cert-byte-flip", "one digit of a certificate's signed issued_at changed; manifest re-hashed", ExpectDetected, f)
	}
	// 1b. Raw byte flip, manifest NOT re-hashed.
	{
		f := clean.Clone()
		b := f[path(a[0])]
		i := bytes.Index(b, []byte(a[0].CertificateID)) + 5
		b[i] ^= 0x01
		add("01b-cert-raw-byte-flip", "one raw byte of a certificate file flipped; manifest untouched", ExpectDetected, f)
	}
	// 2. Signed claim payload edited.
	{
		f := clean.Clone()
		edit(f, a[0], func(d map[string]any) {
			cl := d["claims"].([]any)[0].(map[string]any)
			raw, _ := base64.StdEncoding.DecodeString(cl["canonical_payload"].(string))
			cl["canonical_payload"] = base64.StdEncoding.EncodeToString(bytes.Replace(raw, []byte(Customer), []byte("cust_synthetic_alphX"), 1))
		})
		f.Rehash()
		add("02-claim-payload-edit", "customer id inside a signed claim payload edited; manifest re-hashed", ExpectDetected, f)
	}
	// 3. Swap a certificate for one from another conversation.
	{
		f := clean.Clone()
		swapIn(f, a[2], b[0])
		add("03-swap-cert-other-conversation", "a certificate replaced by a genuine one from another conversation; manifest entry + digests rewritten", ExpectDetected, f)
	}
	// 3b. Swap for another customer's certificate.
	{
		f := clean.Clone()
		swapIn(f, a[2], other)
		add("03b-swap-cert-other-customer", "a certificate replaced by a genuine one of another customer (same conversation id); manifest rewritten", ExpectDetected, f)
	}
	// 4. Drop a certificate file.
	{
		f := clean.Clone()
		delete(f, path(a[1]))
		add("04-drop-cert", "one certificate file removed; manifest untouched", ExpectDetected, f)
	}
	// 5. Manifest edit: conversation id.
	{
		f := clean.Clone()
		m := f.Manifest()
		m.ConversationID = ConvB
		f.WriteManifest(m)
		add("05-manifest-edit-conversation", "manifest conversation_id changed to another conversation", ExpectDetected, f)
	}
	// 6. Manifest digest mismatch.
	{
		f := clean.Clone()
		var m map[string]any
		_ = json.Unmarshal(f[bundle.PathManifest], &m)
		files := m["files"].([]any)
		e := files[0].(map[string]any)
		s := e["sha256"].(string)
		e["sha256"] = strings.Repeat("0", 8) + s[8:]
		f[bundle.PathManifest], _ = json.MarshalIndent(m, "", "  ")
		add("06-manifest-hash-mismatch", "one manifest digest altered", ExpectDetected, f)
	}
	// 7. TSA token replaced with garbage.
	{
		f := clean.Clone()
		junk := make([]byte, 512)
		_, _ = rand.Read(junk)
		edit(f, a[0], func(d map[string]any) {
			att(d)["timestamp"].(map[string]any)["timestamp_token"] = base64.StdEncoding.EncodeToString(junk)
		})
		f.Rehash()
		add("07-tsa-token-replaced", "timestamp token replaced by random bytes; manifest re-hashed", ExpectDetected, f)
	}
	// 8. TSA token for other bytes (genuine token, same TSA).
	{
		f := clean.Clone()
		other := sha256.Sum256([]byte("some other bytes"))
		tok, err := w.Timestamp(other[:], a[0].IssuedAt.Add(2*time.Second))
		if err != nil {
			return nil, err
		}
		edit(f, a[0], func(d map[string]any) {
			att(d)["timestamp"].(map[string]any)["timestamp_token"] = base64.StdEncoding.EncodeToString(tok)
		})
		f.Rehash()
		add("08-tsa-token-other-bytes", "a genuine token from the same TSA over other bytes; manifest re-hashed", ExpectDetected, f)
	}
	// 9. Rekor entry replaced (SET re-signed by an unknown key, i.e. garbage).
	{
		f := clean.Clone()
		junk := make([]byte, 71)
		_, _ = rand.Read(junk)
		edit(f, a[1], func(d map[string]any) {
			att(d)["transparency_log"].(map[string]any)["signed_entry_timestamp"] = base64.StdEncoding.EncodeToString(junk)
		})
		f.Rehash()
		add("09-rekor-entry-replaced", "Rekor signed entry timestamp replaced; manifest re-hashed", ExpectDetected, f)
	}
	// 10. Rekor entry of another certificate (a sibling in the bundle).
	{
		f := clean.Clone()
		edit(f, a[2], func(d map[string]any) {
			att(d)["transparency_log"] = a[1].Doc["attestation"].(map[string]any)["transparency_log"]
		})
		f.Rehash()
		add("10-rekor-entry-other-cert", "Rekor entry copied from another certificate of the bundle; manifest re-hashed", ExpectDetected, f)
	}
	// 10b. Rekor entry + TSA token of an EARLIER certificate from elsewhere.
	{
		f := clean.Clone()
		edit(f, a[2], func(d map[string]any) {
			d["attestation"] = earlier.Doc["attestation"]
		})
		f.Rehash()
		add("10b-anchors-from-earlier-cert", "both anchors copied from a genuine certificate issued two days earlier (other conversation); manifest re-hashed", ExpectDetected, f)
	}
	// 11. anchor_status=ANCHORED with garbage proofs.
	{
		f := clean.Clone()
		junk := make([]byte, 64)
		_, _ = rand.Read(junk)
		edit(f, a[0], func(d map[string]any) {
			d["anchor_status"] = map[string]any{"status": "ANCHOR_STATUS_ANCHORED", "attempts": 1}
			d["attestation"] = map[string]any{
				"timestamp": map[string]any{"timestamp_token": base64.StdEncoding.EncodeToString(junk), "cert_hash": base64.StdEncoding.EncodeToString(junk[:32])},
				"transparency_log": map[string]any{
					"log_index": "424242", "inclusion_proof": base64.StdEncoding.EncodeToString([]byte(`{"hashes":[],"logIndex":0,"rootHash":"00","treeSize":1}`)),
					"signed_entry_timestamp": base64.StdEncoding.EncodeToString(junk), "canonical_body": base64.StdEncoding.EncodeToString([]byte("{}")), "integrated_time": "1790000000",
				},
			}
		})
		f.Rehash()
		add("11-anchored-status-garbage-proof", "anchor_status ANCHORED with garbage TSA token, SET, proof and body; manifest re-hashed", ExpectDetected, f)
	}
	// 12. PDF changed.
	{
		f := clean.Clone()
		f[bundle.PathReportExternal] = append(append([]byte(nil), SyntheticPDF...), []byte("% edited\n")...)
		add("12-pdf-changed", "report-external.pdf modified; manifest untouched", ExpectDetected, f)
	}
	// 13. Extra unlisted file.
	{
		f := clean.Clone()
		f[bundle.PathReportInternal] = SyntheticPDF
		add("13-extra-unlisted-file", "report-internal.pdf added without a manifest entry", ExpectDetected, f)
	}
	// 13b. Extra file outside the v1 layout.
	{
		f := clean.Clone()
		f["audit/events.json"] = []byte("[]")
		f.Rehash()
		add("13b-extra-file-outside-layout", "audit/events.json added (not a v1 path) and listed", ExpectDetected, f)
	}
	// 14. TSA half moved from a sibling certificate.
	{
		f := clean.Clone()
		edit(f, a[2], func(d map[string]any) {
			att(d)["timestamp"] = a[0].Doc["attestation"].(map[string]any)["timestamp"]
		})
		f.Rehash()
		add("14-tsa-from-sibling", "timestamp (token + recorded digest) copied from another certificate of the bundle; manifest re-hashed", ExpectDetected, f)
	}
	// 15. Anchors stripped while the cert still says ANCHORED.
	{
		f := clean.Clone()
		edit(f, a[0], func(d map[string]any) { d["attestation"] = map[string]any{} })
		f.Rehash()
		add("15-anchors-stripped", "attestation removed, anchor_status still ANCHORED; manifest re-hashed", ExpectDetected, f)
	}
	// 16. Rekor integrated_time edited.
	{
		f := clean.Clone()
		edit(f, a[1], func(d map[string]any) {
			tl := att(d)["transparency_log"].(map[string]any)
			tl["integrated_time"] = fmt.Sprintf("%d", a[1].IssuedAt.Unix()+3600)
		})
		f.Rehash()
		add("16-rekor-time-edited", "Rekor integrated_time moved by one hour; manifest re-hashed", ExpectDetected, f)
	}
	// 17. Completeness downgraded.
	{
		f := clean.Clone()
		m := f.Manifest()
		m.Completeness = bundle.Completeness{Listing: "not_exhausted", Note: "synthetic"}
		f.WriteManifest(m)
		add("17-completeness-partial", "manifest states the bundle is partial", ExpectDetected, f)
	}
	// 18. Unknown witness key id.
	{
		f := clean.Clone()
		edit(f, a[0], func(d map[string]any) { d["witness_key_id"] = "witness_unknown" })
		f.Rehash()
		add("18-unknown-witness-key", "witness_key_id changed to an unpinned id; manifest re-hashed", ExpectDetected, f)
	}
	// 19. Not a zip.
	add("19-not-a-zip", "truncated archive", ExpectDetected, Files{"x": nil}) // replaced below
	co.Cases[len(co.Cases)-1].Zip = clean.Zip()[:200]

	// ---- Round-1 gate (T-1231 S1) reviewer repros: F1, F2, F3, F5, F6, F7 ----
	// F1: inclusion proof without a checkpoint, root fabricated from the
	// body alone (a one-leaf "tree") — Sol P1 / ToB P2.
	{
		f := clean.Clone()
		edit(f, a[1], func(d map[string]any) {
			tl := att(d)["transparency_log"].(map[string]any)
			body, _ := base64.StdEncoding.DecodeString(tl["canonical_body"].(string))
			proof, _ := json.Marshal(map[string]any{"hashes": []string{}, "logIndex": 0, "rootHash": LeafHashHex(body), "treeSize": 1})
			tl["inclusion_proof"] = base64.StdEncoding.EncodeToString(proof)
		})
		f.Rehash()
		add("F1-rekor-no-checkpoint-fabricated-root", "inclusion proof replaced by a one-leaf proof whose root is the entry's own leaf hash, no checkpoint; manifest re-hashed", ExpectDetected, f)
	}
	// F2: attestation AND anchor_status removed from EVERY certificate —
	// bug-hunter P2 / Sol P1 (hosted policy: --require-anchors).
	{
		f := clean.Clone()
		for _, c := range a {
			edit(f, c, func(d map[string]any) {
				delete(d, "attestation")
				delete(d, "anchor_status")
			})
		}
		f.Rehash()
		add("F2-anchors-and-status-stripped-all", "attestation and anchor_status removed from every certificate; manifest re-hashed", ExpectDetected, f)
	}
	// F3: --online with a corrupt STORED inclusion proof; the log serves the
	// genuine entry — Sol P2.
	{
		f := clean.Clone()
		edit(f, a[0], func(d map[string]any) {
			att(d)["transparency_log"].(map[string]any)["inclusion_proof"] = base64.StdEncoding.EncodeToString(
				[]byte(`{"hashes":[],"logIndex":0,"rootHash":"` + strings.Repeat("00", 32) + `","treeSize":1}`))
		})
		f.Rehash()
		add("F3-online-corrupt-stored-proof", "stored inclusion proof corrupted, verified with --online against a log serving the genuine entry; manifest re-hashed", ExpectDetected, f)
		co.Cases[len(co.Cases)-1].Flags = online
	}
	// F5: a required file missing, manifest rewritten to match — Sol P2.
	for _, rm := range []struct{ name, path string }{
		{"F5-missing-report-external", bundle.PathReportExternal},
		{"F5b-missing-readme", bundle.PathReadme},
	} {
		f := clean.Clone()
		delete(f, rm.path)
		f.Rehash()
		add(rm.name, rm.path+" removed and its manifest entry dropped (digests recomputed)", ExpectDetected, f)
	}
	{
		f := clean.Clone()
		delete(f, bundle.PathManifest)
		add("F5c-missing-manifest", "manifest.json removed", ExpectDetected, f)
	}
	{
		f := clean.Clone()
		m := f.Manifest()
		for _, c := range m.Certificates {
			delete(f, c.Path)
		}
		m.Certificates = nil
		f.WriteManifest(m)
		add("F5d-no-certificates", "every certificate and certificate entry removed, manifest rewritten", ExpectDetected, f)
	}
	// F6: directory entries are never skipped — Sol P2.
	add("F6-zip-dir-entry-traversal", "clean bundle plus an empty directory entry ../../outside/", ExpectDetected, clean.Clone())
	co.Cases[len(co.Cases)-1].Zip = clean.ZipWithDirs("../../outside/")
	add("F6b-zip-dir-entry-certificates", "clean bundle plus an empty directory entry certificates/", ExpectDetected, clean.Clone())
	co.Cases[len(co.Cases)-1].Zip = clean.ZipWithDirs(bundle.DirCertificates)
	// F7: case-variant duplicate manifest key: a JavaScript reader takes the
	// FIRST conversation_id (another conversation), Go took the LAST —
	// bug-hunter P3.
	{
		f := clean.Clone()
		mb := f[bundle.PathManifest]
		orig := []byte(`"conversation_id": "` + ConvA + `"`)
		if !bytes.Contains(mb, orig) {
			return nil, fmt.Errorf("corpus: manifest lacks %s", orig)
		}
		f[bundle.PathManifest] = bytes.Replace(mb, orig, []byte(`"conversation_id": "`+ConvB+`",
  "Conversation_ID": "`+ConvA+`"`), 1)
		add("F7-manifest-case-variant-key", "manifest carries conversation_id (another conversation) and a later case-variant Conversation_ID (this one)", ExpectDetected, f)
	}
	// The clean bundle with --online must stay VALID.
	add("00-clean-online", "untouched bundle, --online against the synthetic log", ExpectValid, clean.Clone())
	co.Cases[len(co.Cases)-1].Flags = online

	// Documented v1 limits — measured, expected to exit 0.
	{
		f := clean.Clone()
		delete(f, path(a[1]))
		m := f.Manifest()
		var keep []bundle.ManifestCert
		for _, c := range m.Certificates {
			if c.RequestID != a[1].RequestID {
				keep = append(keep, c)
			}
		}
		m.Certificates = keep
		f.WriteManifest(m)
		add("G1-drop-cert-and-entry", "a certificate removed TOGETHER with its manifest entry, digests recomputed (closed by the Slice 2 counter)", ExpectKnownGap, f)
	}
	{
		f := clean.Clone()
		edit(f, a[2], func(d map[string]any) { d["attestation"] = later.Doc["attestation"] })
		f.Rehash()
		add("G2-anchors-from-later-cert", "both anchors copied from a genuine certificate of the same witness issued LATER — pre-binding certificates only (issued before the cutover, anchors without binding v1); closed for binding-v1 certificates, see S2a-01", ExpectKnownGap, f)
	}
	{
		f := clean.Clone()
		f[bundle.PathReportExternal] = append(append([]byte(nil), SyntheticPDF...), []byte("% a different report body\n")...)
		f.Rehash()
		add("G3-report-replaced-and-rehashed", "report-external.pdf replaced AND its manifest digest updated (the manifest is unsigned in format 1; reported as 'report content not authenticated')", ExpectKnownGap, f)
	}

	// ---- T-1231 S2a: content-bound anchors (binding v1) ----
	cleanBound := Build(Spec{ConversationID: ConvA, CustomerID: Customer, Certs: ab})
	ts := func(doc map[string]any) map[string]any { return att(doc)["timestamp"].(map[string]any) }
	add("S2a-00-clean-bound", "untouched bundle of 3 binding-v1 certificates issued after the cutover", ExpectValid, cleanBound.Clone())
	{
		f := cleanBound.Clone()
		edit(f, ab[2], func(d map[string]any) { d["attestation"] = laterBound.Doc["attestation"] })
		f.Rehash()
		add("S2a-01-G2-anchors-from-later-bound-cert", "G2 on binding-v1 certificates: both anchors (and their cert_hash) copied from a genuine bound certificate of the same witness issued LATER; manifest re-hashed", ExpectDetected, f)
	}
	{
		f := cleanBound.Clone()
		edit(f, ab[0], func(d map[string]any) { ts(d)["hash_algorithm"] = "SHA-256" })
		f.Rehash()
		add("S2a-02-binding-marker-stripped", "post-cutover certificate: binding marker rewritten to the legacy SHA-256; manifest re-hashed", ExpectDetected, f)
	}
	{
		f := cleanBound.Clone()
		edit(f, ab[1], func(d map[string]any) { delete(ts(d), "hash_algorithm") })
		f.Rehash()
		add("S2a-03-binding-marker-removed", "post-cutover certificate: binding marker removed; manifest re-hashed", ExpectDetected, f)
	}
	{
		f := cleanBound.Clone()
		edit(f, ab[2], func(d map[string]any) { ts(d)["hash_algorithm"] = "lucairn.anchor-binding/v2" })
		f.Rehash()
		add("S2a-04-unknown-binding-version", "binding marker changed to an unknown version (v2); manifest re-hashed", ExpectDetected, f)
	}
	add("S2a-05-post-cutover-unbound-anchors", "a genuine certificate issued after the cutover but anchored WITHOUT binding v1 (downgrade)", ExpectDetected,
		Build(Spec{ConversationID: ConvA, CustomerID: Customer, Certs: []*Cert{ab[0], ab[1], postCutoverUnbound}}))
	{
		f := cleanBound.Clone()
		edit(f, ab[1], func(d map[string]any) {
			h, _ := base64.StdEncoding.DecodeString(ts(d)["cert_hash"].(string))
			h[0] ^= 1
			ts(d)["cert_hash"] = base64.StdEncoding.EncodeToString(h)
		})
		f.Rehash()
		add("S2a-06-bound-cert-hash-edited", "binding-v1 certificate: recorded cert_hash edited (an input to the binding digest); manifest re-hashed", ExpectDetected, f)
	}
	{
		f := cleanBound.Clone()
		edit(f, ab[1], func(d map[string]any) {
			att(d)["transparency_log"] = laterBound.Doc["attestation"].(map[string]any)["transparency_log"]
		})
		f.Rehash()
		add("S2a-07-rekor-from-later-bound-cert", "binding-v1 certificate: only the Rekor entry copied from a later bound certificate; manifest re-hashed", ExpectDetected, f)
	}
	add("S2a-08-pre-cutover-bound-valid", "a binding-v1 certificate issued BEFORE the cutover (deploy-to-cutover window) next to a legacy one: content-bound + not-content-bound lines", ExpectValid,
		Build(Spec{ConversationID: ConvA, CustomerID: Customer, Certs: []*Cert{a[0], preCutoverBound}}))
	{
		f := clean.Clone()
		edit(f, a[0], func(d map[string]any) { ts(d)["hash_algorithm"] = "lucairn.anchor-binding/v1" })
		f.Rehash()
		add("S2a-09-binding-marker-on-legacy-anchors", "pre-cutover legacy certificate relabelled binding v1 (anchors are over cert_hash, not the binding digest); manifest re-hashed", ExpectDetected, f)
	}

	// ---- T-1231 S2a fix round (Sol #747 P1, D3) ----
	// Sol P1 shape: a genuine certificate carries ANOTHER bound certificate's
	// anchors, relabelled legacy (hash_algorithm "SHA-256") with
	// cert_hash := that certificate's binding digest H — the legacy checks
	// alone would accept the TSA token (imprint == recorded cert_hash).
	relabel := func(donor *Cert) func(d map[string]any) {
		return func(d map[string]any) {
			var at map[string]any
			b, _ := json.Marshal(donor.Doc["attestation"])
			_ = json.Unmarshal(b, &at)
			ts := at["timestamp"].(map[string]any)
			ts["hash_algorithm"] = "SHA-256"
			ts["cert_hash"] = base64.StdEncoding.EncodeToString(donor.H)
			d["attestation"] = at
		}
	}
	{
		f := cleanBound.Clone()
		edit(f, ab[0], relabel(laterBound))
		f.Rehash()
		add("S2a-10-solp1-relabelled-post-cutover", "Sol #747 P1: a later bound certificate's anchors relabelled legacy with cert_hash := its binding digest, on a certificate issued after the cutover; manifest re-hashed", ExpectDetected, f)
	}
	{
		f := clean.Clone()
		edit(f, a[2], relabel(preCutoverBound))
		f.Rehash()
		add("S2a-11-solp1-relabelled-pre-cutover", "Sol #747 P1 before the cutover: a later bound certificate's anchors relabelled legacy on a legacy certificate; caught by the Rekor entry logging sha512(cert_hash); manifest re-hashed", ExpectDetected, f)
	}
	{
		f := clean.Clone()
		edit(f, a[2], func(d map[string]any) {
			relabel(preCutoverBound)(d)
			delete(att(d), "transparency_log")
		})
		f.Rehash()
		add("S2a-12-solp1-pre-cutover-tsa-only", "Sol #747 P1 before the cutover with the Rekor entry dropped: only the relabelled token is left (hosted policy: a missing anchor is INCOMPLETE); manifest re-hashed", ExpectDetected, f)
	}
	{
		ro := *rekorOnly
		var doc map[string]any
		b, _ := json.Marshal(rekorOnly.Doc)
		_ = json.Unmarshal(b, &doc)
		ts := doc["attestation"].(map[string]any)["timestamp"].(map[string]any)
		ts["timestamp_token"], ts["provider"] = "", ""
		doc["anchor_status"] = map[string]any{"status": "ANCHOR_STATUS_FAILED", "attempts": 3}
		ro.Doc = doc
		if err := ro.Remarshal(); err != nil {
			return nil, err
		}
		co.RekorOnly = &ro
		addF("S2a-13b-rekor-only-allow-unanchored", "the S2a-13 certificate under --allow-unanchored: the honest Rekor-only certificate stays acceptable (VALID)", ExpectValid,
			Build(Spec{ConversationID: ConvA, CustomerID: Customer, Certs: []*Cert{ab[0], &ro}}), FlagAllowUnanchored)
		add("S2a-13-rekor-only-hosted-incomplete", "a binding-v1 certificate whose TSA rail failed (cert_hash + marker kept, no token): Rekor PASS (content-bound), the missing timestamp is INCOMPLETE under the hosted policy (VALID with --allow-unanchored, see TestRekorOnlyBoundCertificate)", ExpectDetected,
			Build(Spec{ConversationID: ConvA, CustomerID: Customer, Certs: []*Cert{ab[0], &ro}}))
	}

	// ---- T-1231 S2a round 3 (Sol #77 P1) ----
	// A post-cutover certificate with its marker relabelled legacy and BOTH
	// anchors plus anchor_status removed. Before round 3 the anchor steps
	// returned "not anchored" before the binding rule ran: INCOMPLETE by
	// default and VALID with --allow-unanchored. The marker rule must hold
	// independently of anchor presence: TAMPERED under both policies.
	stripAll := func(removeAttestation bool) func(d map[string]any) {
		return func(d map[string]any) {
			delete(d, "anchor_status")
			if removeAttestation {
				delete(d, "attestation")
				return
			}
			t := ts(d)
			t["hash_algorithm"] = "SHA-256"
			t["timestamp_token"], t["provider"] = "", ""
			delete(att(d), "transparency_log")
		}
	}
	for _, v := range []struct {
		name, what string
		removeAtt  bool
	}{
		{"S2a-14-solp1-77-legacy-marker-no-anchors", "Sol #77 P1: post-cutover certificate relabelled legacy (SHA-256) with the timestamp token, the Rekor entry and anchor_status removed; manifest re-hashed", false},
		{"S2a-16-attestation-removed", "post-cutover certificate with its whole attestation (marker, cert_hash, both anchors) and anchor_status removed; manifest re-hashed", true},
	} {
		for _, pol := range []struct {
			suffix string
			flags  []string
		}{{"", nil}, {"-allow-unanchored", []string{FlagAllowUnanchored}}} {
			f := cleanBound.Clone()
			edit(f, ab[1], stripAll(v.removeAtt))
			f.Rehash()
			what := v.what
			if pol.flags != nil {
				what += " (run with --allow-unanchored)"
			}
			addF(v.name+pol.suffix, what, ExpectTampered, f, pol.flags...)
		}
	}
	// ---- T-1231 S2b: format 2 (audit counter, inclusion, anchored roots) ----
	if err := addAuditCases(co); err != nil {
		return nil, err
	}
	return co, nil
}
