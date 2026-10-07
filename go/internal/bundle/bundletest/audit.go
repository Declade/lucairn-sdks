package bundletest

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/anchor"
	"github.com/declade/lucairn-sdks/go/internal/bundle"
	"github.com/declade/lucairn-sdks/go/internal/verify"
)

// AuditService is the service id of the synthetic audit key (claims and
// audit roots).
const AuditService = "dsa-audit"

// AuditLog is a SYNTHETIC audit service (T-1231 S2b): one append-only log of
// event hashes, the per-conversation counter, and hourly-style root
// publications logged in the synthetic Rekor.
//
// Its Merkle tree is built the way the real audit service builds it — level
// by level, an odd node promoted unchanged (dual-sandbox-architecture
// services/audit/internal/merkle) — NOT with the RFC 6962 recursion the tool
// verifies with. The corpus therefore also measures that the two shapes
// agree (see also anchor's TestAuditTreeEqualsRFC6962).
type AuditLog struct {
	w *World
	// hashes is every row's event_hash in log order (leaf i = hashes[i]).
	hashes []string
	seqs   map[string]uint64
	rows   map[string][]bundle.AuditEvent
	// Roots are the published (anchored) roots, in publication order.
	Roots []*AuditRootPub
	// Entries are the synthetic log's entries of the published roots, by
	// global log index (what --online fetches).
	Entries map[int64]*bundle.FetchedEntry
}

// AuditRootPub is one published audit root.
type AuditRootPub struct {
	// ID is the publication's id (audit_checkpoints.id): what an event's
	// root_ref names. Deliberately unrelated to the tree size.
	ID        uint64
	TreeSize  uint64
	Root      []byte
	Artifact  []byte
	Signature []byte
	// Rekor is the rekor_entry object as audit/roots.json carries it.
	Rekor map[string]any
}

// NewAuditLog starts an empty synthetic audit log.
func (w *World) NewAuditLog() *AuditLog {
	return &AuditLog{w: w, seqs: map[string]uint64{}, rows: map[string][]bundle.AuditEvent{}, Entries: map[int64]*bundle.FetchedEntry{}}
}

func (l *AuditLog) head() string {
	if len(l.hashes) == 0 {
		return ""
	}
	return l.hashes[len(l.hashes)-1]
}

// Filler appends n uncounted rows of other traffic (v1-style hashes).
func (l *AuditLog) Filler(n int) {
	for i := 0; i < n; i++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s|synthetic uncounted audit row %d", l.head(), len(l.hashes))))
		l.hashes = append(l.hashes, hex.EncodeToString(h[:]))
	}
}

func syntheticEvent(conv, reqID, customer string) bundle.AuditEvent {
	idh := sha256.Sum256([]byte(reqID))
	payload := sha256.Sum256([]byte(`{"conversation_id":"` + conv + `","customer_id":"` + customer + `","request_id":"` + reqID + `","status":"synthetic"}`))
	return bundle.AuditEvent{
		ConversationID: conv, RequestID: reqID,
		EventID: "evt_completion_" + hex.EncodeToString(idh[:]), EventType: "PROXY_INFERENCE_COMPLETED",
		SourceService: "gateway", Actor: customer, PayloadSHA256: hex.EncodeToString(payload[:]),
	}
}

// Record appends the COUNTED terminal event of one request: the next
// conv_seq of its conversation, hashed with the v2 serialisation.
func (l *AuditLog) Record(conv, reqID, customer string) bundle.AuditEvent {
	e := syntheticEvent(conv, reqID, customer)
	return l.record(e)
}

func (l *AuditLog) record(e bundle.AuditEvent) bundle.AuditEvent {
	conv := e.ConversationID
	l.seqs[conv]++
	e.ConvSeq = l.seqs[conv]
	e.PreviousEventHash = l.head()
	e.EventHash = bundle.EventHashV2(e)
	e.LeafIndex = uint64(len(l.hashes))
	l.hashes = append(l.hashes, e.EventHash)
	l.rows[conv] = append(l.rows[conv], e)
	return e
}

// RecordUncounted appends a terminal event from before counting started: a
// row with no counter entry. Only its event_hash matters to a bundle.
func (l *AuditLog) RecordUncounted(conv, reqID, customer string) bundle.AuditEvent {
	e := syntheticEvent(conv, reqID, customer)
	h := sha256.Sum256([]byte(l.head() + "v1|" + e.EventID + "|" + e.PayloadSHA256))
	e.EventHash = hex.EncodeToString(h[:])
	l.hashes = append(l.hashes, e.EventHash)
	return e
}

// leaves are the tree's leaf hashes for the first size rows.
func (l *AuditLog) leaves(size uint64) [][]byte {
	out := make([][]byte, size)
	for i := range out {
		out[i] = anchor.AuditLeafHash(l.hashes[i])
	}
	return out
}

// AuditTreeLevels builds the audit service's tree over leaves, level by
// level, promoting an odd node unchanged (services/audit/internal/merkle
// computeRoot / ProofsAt). levels[0] are the leaves, the last level is the
// root.
func AuditTreeLevels(leaves [][]byte) [][][]byte {
	level := leaves
	levels := [][][]byte{level}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, node(level[i], level[i+1]))
			} else {
				next = append(next, level[i])
			}
		}
		levels = append(levels, next)
		level = next
	}
	return levels
}

// AuditTreePath is the audit service's audit path of leaf index in a tree
// built by AuditTreeLevels: the sibling at every level that has one (no
// left/right flags).
func AuditTreePath(levels [][][]byte, index uint64) [][]byte {
	path := [][]byte{}
	for _, lvl := range levels[:len(levels)-1] {
		if sib := index ^ 1; sib < uint64(len(lvl)) {
			path = append(path, lvl[sib])
		}
		index /= 2
	}
	return path
}

// RFC6962Root and RFC6962Path are the RFC 6962 § 2.1 recursion (split at the
// largest power of two below n) — an independent second implementation.
func RFC6962Root(leaves [][]byte) []byte { return mth(leaves) }

// RFC6962Path is the RFC 6962 § 2.1.1 audit path of leaf m.
func RFC6962Path(m int, leaves [][]byte) [][]byte { return inclusionPath(m, leaves) }

// Publish signs the root of the current tree with the audit key and logs it
// in the synthetic Rekor at time at.
func (l *AuditLog) Publish(at time.Time) (*AuditRootPub, error) {
	return l.PublishBy(l.w.Services[AuditService], l.w.Services[AuditService], at)
}

// PublishBy is Publish with the root signature made by sigKey and the Rekor
// entry made by logKey (negative tests: a key that is not the pinned one).
// The publication is returned and, when both keys are the audit key,
// recorded as an anchored root.
func (l *AuditLog) PublishBy(sigKey, logKey ed25519.PrivateKey, at time.Time) (*AuditRootPub, error) {
	size := uint64(len(l.hashes))
	if size == 0 {
		return nil, fmt.Errorf("empty audit log")
	}
	levels := AuditTreeLevels(l.leaves(size))
	root := levels[len(levels)-1][0]
	artifact := anchor.AuditRootArtifact(size, root)
	digest := sha512.Sum512(artifact)
	sig, err := sigKey.Sign(rand.Reader, digest[:], crypto.SHA512)
	if err != nil {
		return nil, err
	}
	l.w.rootEntries++
	logIndex := int64(500000 + l.w.rootEntries)
	tl, err := l.w.rekorEntryBy(logKey, artifact, at, logIndex)
	if err != nil {
		return nil, err
	}
	dec := func(k string) []byte {
		b, _ := base64.StdEncoding.DecodeString(tl[k].(string))
		return b
	}
	pub := &AuditRootPub{ID: uint64(40 + l.w.rootEntries), TreeSize: size, Root: root, Artifact: artifact, Signature: sig, Rekor: map[string]any{
		"log_index": json.Number(strconv.FormatInt(logIndex, 10)), "integrated_time": json.Number(strconv.FormatInt(at.Unix(), 10)),
		"canonical_body": tl["canonical_body"], "signed_entry_timestamp": tl["signed_entry_timestamp"],
		"inclusion_proof": tl["inclusion_proof"], "log_url": tl["log_url"],
		"uuid": fmt.Sprintf("synthetic-%d", logIndex), "log_id": l.w.rekorKey.LogID,
	}}
	sameKey := func(a, b ed25519.PrivateKey) bool { return string(a) == string(b) }
	if sameKey(sigKey, l.w.Services[AuditService]) && sameKey(logKey, l.w.Services[AuditService]) {
		l.Roots = append(l.Roots, pub)
		l.Entries[logIndex] = &bundle.FetchedEntry{Body: dec("canonical_body"), IntegratedTime: at.Unix(), LogIndex: logIndex,
			SignedEntryTimestamp: dec("signed_entry_timestamp"), InclusionProof: dec("inclusion_proof")}
	}
	return pub, nil
}

// Evidence is what an exporter writes into audit/ for one conversation.
type Evidence struct {
	Events []bundle.AuditEvent
	// Proofs by conv_seq (anchored events only).
	Proofs map[uint64]bundle.AuditProof
	Roots  []*AuditRootPub
}

// Evidence returns the counted rows of conv in counter order, each proven
// against the EARLIEST published root that covers it (rows newer than the
// latest root are left unanchored), plus those roots.
func (l *AuditLog) Evidence(conv string) *Evidence {
	ev := &Evidence{Proofs: map[uint64]bundle.AuditProof{}}
	used := map[uint64]*AuditRootPub{}
	levelsAt := map[uint64][][][]byte{}
	for _, e := range l.rows[conv] {
		for _, r := range l.Roots {
			if r.TreeSize > e.LeafIndex && (used[r.TreeSize] == nil || used[r.TreeSize] == r) {
				if levelsAt[r.TreeSize] == nil {
					levelsAt[r.TreeSize] = AuditTreeLevels(l.leaves(r.TreeSize))
				}
				e.RootRef = r.ID
				ev.Proofs[e.ConvSeq] = bundle.AuditProof{LeafIndex: e.LeafIndex, TreeSize: r.TreeSize, Path: AuditTreePath(levelsAt[r.TreeSize], e.LeafIndex)}
				used[r.TreeSize] = r
				break
			}
		}
		ev.Events = append(ev.Events, e)
	}
	sizes := make([]uint64, 0, len(used))
	for s := range used {
		sizes = append(sizes, s)
	}
	sort.Slice(sizes, func(i, j int) bool { return sizes[i] < sizes[j] })
	for _, s := range sizes {
		ev.Roots = append(ev.Roots, used[s])
	}
	return ev
}

func num(v uint64) json.Number { return json.Number(strconv.FormatUint(v, 10)) }

// EventJSON is one audit/events.json entry, in the shape of the gateway's
// evidence response (api-contract.md): root_ref is the root's id, 0 when the
// event is not anchored yet.
func EventJSON(e bundle.AuditEvent) map[string]any {
	return map[string]any{
		"conv_seq": num(e.ConvSeq), "conversation_id": e.ConversationID, "request_id": e.RequestID,
		"event_id": e.EventID, "event_type": e.EventType, "source_service": e.SourceService, "actor": e.Actor,
		"payload_sha256": e.PayloadSHA256, "previous_event_hash": e.PreviousEventHash, "event_hash": e.EventHash,
		"leaf_index": num(e.LeafIndex), "root_ref": num(e.RootRef),
		"recorded_at": "2026-10-02T15:05:00.000000Z",
	}
}

// ProofJSON is one audit/proofs.json entry (path elements as 64 lowercase
// hex characters, api-contract.md section 2a).
func ProofJSON(seq uint64, p bundle.AuditProof) map[string]any {
	path := []any{}
	for _, h := range p.Path {
		path = append(path, hex.EncodeToString(h))
	}
	return map[string]any{"conv_seq": num(seq), "leaf_index": num(p.LeafIndex), "tree_size": num(p.TreeSize), "path": path}
}

// RootJSON is one audit/roots.json entry.
func RootJSON(r *AuditRootPub) map[string]any {
	return map[string]any{
		"id": num(r.ID), "tree_size": num(r.TreeSize), "root_hash": hex.EncodeToString(r.Root),
		"root_artifact":  base64.StdEncoding.EncodeToString(r.Artifact),
		"root_signature": base64.StdEncoding.EncodeToString(r.Signature),
		// A label only; the tool always uses its pinned dsa-audit key.
		"signing_key_id": AuditService + ":synthetic", "rekor_entry": r.Rekor,
		"published_at": "2026-10-02T16:00:07Z",
	}
}

// WriteTo writes the three audit files into f.
func (ev *Evidence) WriteTo(f Files) {
	events := []any{}
	for _, e := range ev.Events {
		events = append(events, EventJSON(e))
	}
	seqs := make([]uint64, 0, len(ev.Proofs))
	for s := range ev.Proofs {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	proofs := []any{}
	for _, s := range seqs {
		proofs = append(proofs, ProofJSON(s, ev.Proofs[s]))
	}
	roots := []any{}
	for _, r := range ev.Roots {
		roots = append(roots, RootJSON(r))
	}
	f.PutList(bundle.PathAuditEvents, events)
	f.PutList(bundle.PathAuditProofs, proofs)
	f.PutList(bundle.PathAuditRoots, roots)
}

// PutList writes one audit file in its pinned form: a top-level object with
// the file's single key ("events" / "proofs" / "roots") holding the array
// (api-contract.md section 2a).
func (f Files) PutList(path string, list []any) {
	if list == nil {
		list = []any{}
	}
	f.PutJSON(path, map[string]any{bundle.AuditListKeys[path]: list})
}

// List decodes the array of an audit file (number lexemes kept).
func (f Files) List(path string) []any {
	doc, err := verify.DecodeDocument(f[path])
	if err != nil {
		panic(err)
	}
	return doc.(map[string]any)[bundle.AuditListKeys[path]].([]any)
}

// PutJSON writes v as indented JSON at path.
func (f Files) PutJSON(path string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	f[path] = append(b, '\n')
}

// EditList decodes the array of an audit file (number lexemes kept), lets fn
// change it, and writes it back in the pinned form. The manifest is NOT
// re-hashed.
func (f Files) EditList(path string, fn func(list []any) []any) {
	f.PutList(path, fn(f.List(path)))
}

// auditClaim records the request's terminal audit event and builds the
// dsa-audit EVENTS_RECORDED claim that signs its event_hash (two claims with
// CertOptions.ExtraAuditSeq).
func (w *World) auditClaim(o CertOptions, n int, reqID string, issued time.Time) ([]map[string]any, *bundle.AuditEvent, error) {
	var e bundle.AuditEvent
	if o.Uncounted {
		e = o.Audit.RecordUncounted(o.ConversationID, reqID, o.CustomerID)
	} else {
		e = o.Audit.Record(o.ConversationID, reqID, o.CustomerID)
	}
	size := uint64(len(o.Audit.hashes))
	levels := AuditTreeLevels(o.Audit.leaves(size))
	payload := map[string]any{
		"event_hash": e.EventHash, "event_id": e.EventID, "event_type": e.EventType, "source_service": e.SourceService,
		"merkle_root": hex.EncodeToString(levels[len(levels)-1][0]), "merkle_tree_size": num(size),
	}
	if !o.NoSignedCounter && !o.Uncounted {
		payload["conversation_id"], payload["conv_seq"] = e.ConversationID, num(e.ConvSeq)
	}
	ts := issued.Add(-1 * time.Second).Format("2006-01-02T15:04:05.000000000Z")
	claim, err := w.signAuditClaim(fmt.Sprintf("clm_synthetic-audit-%04d", n), reqID, ts, payload)
	if err != nil {
		return nil, nil, err
	}
	claims := []map[string]any{claim}
	if o.ExtraAuditSeq != 0 {
		// A second, equally valid audit-signed claim for the SAME audit row
		// that signs another number.
		extra := map[string]any{}
		for k, v := range payload {
			extra[k] = v
		}
		extra["conversation_id"], extra["conv_seq"] = e.ConversationID, num(o.ExtraAuditSeq)
		c2, err := w.signAuditClaim(fmt.Sprintf("clm_synthetic-audit-%04d-b", n), reqID, ts, extra)
		if err != nil {
			return nil, nil, err
		}
		claims = append(claims, c2)
	}
	if o.Uncounted {
		return claims, nil, nil
	}
	return claims, &e, nil
}

// signAuditClaim builds one dsa-audit EVENTS_RECORDED claim over payload,
// signed with the synthetic audit key.
func (w *World) signAuditClaim(claimID, reqID, ts string, payload map[string]any) (map[string]any, error) {
	dataSeen, dataNotSeen := []string{"event_hashes"}, []string{"pii", "context", "inference_result"}
	canon, err := verify.CanonicalLexeme(map[string]any{
		"claim_id": claimID, "request_id": reqID, "service_id": AuditService,
		"claim_type": "EVENTS_RECORDED", "data_seen": dataSeen, "data_not_seen": dataNotSeen,
		"payload": payload, "timestamp": ts,
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"claim_id": claimID, "request_id": reqID, "service_id": AuditService,
		"claim_type": "CLAIM_TYPE_EVENTS_RECORDED", "data_seen": dataSeen, "data_not_seen": dataNotSeen,
		"canonical_payload": base64.StdEncoding.EncodeToString(canon),
		"signature":         base64.StdEncoding.EncodeToString(ed25519.Sign(w.Services[AuditService], canon)),
		"timestamp":         ts,
	}, nil
}

// AnchorRoot converts a published root into the verifier's input form.
func AnchorRoot(r *AuditRootPub) anchor.AuditRoot {
	dec := func(k string) []byte {
		b, _ := base64.StdEncoding.DecodeString(r.Rekor[k].(string))
		return b
	}
	n := func(k string) int64 {
		v, _ := r.Rekor[k].(json.Number).Int64()
		return v
	}
	return anchor.AuditRoot{Artifact: r.Artifact, Signature: r.Signature, Entry: anchor.RekorEntry{
		LogIndex: n("log_index"), IntegratedTime: n("integrated_time"), CanonicalBody: dec("canonical_body"),
		SignedEntryTimestamp: dec("signed_entry_timestamp"), InclusionProof: dec("inclusion_proof"),
	}}
}
