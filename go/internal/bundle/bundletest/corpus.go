package bundletest

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
)

// Case is one corpus entry.
type Case struct {
	Name   string
	What   string
	Expect string
	Zip    []byte
}

// Corpus is the synthetic world plus every case.
type Corpus struct {
	World *World
	Cases []Case
	// Clean is the clean bundle's files; Originals are the synthetic
	// "original values" no bundle file may contain.
	Clean Files
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
	if err != nil {
		return nil, err
	}
	clean := Build(Spec{ConversationID: ConvA, CustomerID: Customer, Certs: a})
	co := &Corpus{World: w, Clean: clean}
	add := func(name, what, expect string, f Files) {
		co.Cases = append(co.Cases, Case{Name: name, What: what, Expect: expect, Zip: f.Zip()})
	}
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
		m.Completeness = bundle.Completeness{State: "partial", Note: "synthetic"}
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
		add("G2-anchors-from-later-cert", "both anchors copied from a genuine certificate of the same witness issued LATER (content binding is not provable from the bundle)", ExpectKnownGap, f)
	}
	return co, nil
}
