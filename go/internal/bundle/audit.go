package bundle

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/anchor"
	"github.com/declade/lucairn-sdks/go/internal/verify"
)

// The audit/ folder of a format-2 bundle (T-1231 S2b). Design:
// specs/2026-10/design-2026-10-06-t1231-s2b-audit-counter.md §4.4, §5; wire
// shapes: specs/2026-10/evidence/t1231-s2b/api-contract.md (the gateway's
// evidence response, split into three files by the website).
//
// Everything in these three files is UNSIGNED bundle content. What makes an
// entry evidence is, in this order:
//
//   - the dsa-audit signature every certificate already carries: its
//     EVENTS_RECORDED claim signs the audit row's event_hash, and event_hash
//     is a hash over the counter (conversation_id + conv_seq); for a counted
//     request the claim payload also names conversation_id and conv_seq
//     themselves (design D3) — so the number is covered by a signature the
//     tool verifies under a pinned key;
//   - the anchored audit root: the row's event_hash is a leaf of the audit
//     tree whose root the audit key signed and Rekor logged.
//
// Each file is ONE top-level JSON object with exactly ONE key — "events",
// "proofs" or "roots" — whose value is an array (api-contract.md section 2a,
// pinned). A bare array, another key name, a second key, null in place of the
// array: all TAMPERED. An empty list is written [] and its key is still there.
//
// # audit/events.json — {"events":[...]}, one entry per counted request, ordered by conv_seq
//
//	{ "conv_seq": 1,                        JSON integer >= 1
//	  "conversation_id": "<32 lowercase hex>",
//	  "request_id": "...",                  "" when the audit row has none
//	  "event_id": "...", "event_type": "...", "source_service": "...", "actor": "...",
//	  "payload_sha256": "<64 lowercase hex>",
//	  "previous_event_hash": "<64 lowercase hex, or \"\" for the first row of a log>",
//	  "event_hash": "<64 lowercase hex>",
//	  "leaf_index": 84011,                  JSON integer >= 0: position in the whole audit log
//	  "root_ref": 17,                       the "id" of the root in audit/roots.json this
//	                                        row is proven against; 0 = not anchored yet
//	  "recorded_at": "..." }                optional, informational (not in event_hash)
//
// No payload is carried (design D12: digest only).
//
// # audit/proofs.json — {"proofs":[...]}, one entry per event with a root_ref
//
//	{ "conv_seq": 1, "leaf_index": 84011, "tree_size": 84020,
//	  "path": ["<64 lowercase hex characters = 32 bytes>", ...] }
//
// path is the RFC 6962 audit path (sibling hashes, leaf to root). Its elements
// are lowercase hex and nothing else (api-contract.md section 2a): base64 or
// upper-case hex is TAMPERED, so one path has one spelling. There are no
// left/right flags: index and size decide the side
// (anchor.AuditInclusionRoot). leaf_index and tree_size here are UNSIGNED
// copies: the tool takes the leaf index from the event entry and the tree
// size ONLY from the signed root artifact, and a copy that differs is
// TAMPERED — an inclusion path alone does not pin the tree size (several
// sizes share one path shape). An event without a root_ref has no entry (an
// entry with tree_size 0 and an empty path is read as "no proof").
//
// # audit/roots.json — {"roots":[...]}, the roots the events reference
//
//	{ "id": 17, "tree_size": 84020, "root_hash": "<64 lowercase hex>",
//	  "root_artifact": "<base64 of the exact signed bytes>",
//	  "root_signature": "<base64, Ed25519ph over sha512(artifact)>",
//	  "signing_key_id": "dsa-audit:<hex>",   a label; the pinned dsa-audit key is always used
//	  "rekor_entry": {
//	     "log_index": 123, "integrated_time": 1790000000,     JSON integers
//	     "canonical_body": "<base64>", "signed_entry_timestamp": "<base64>",
//	     "inclusion_proof": "<base64 of Rekor's inclusionProof JSON, checkpoint included>",
//	     "log_url": "...", "uuid": "...", "log_id": "..." },   optional, informational
//	  "published_at": "..." }                optional, informational
//
// A deployment without anchoring writes {"proofs":[]} and {"roots":[]}.
//
// Every object's key set is exact and case-sensitive; integers are JSON
// integers (no strings, no exponent, no leading zero). A file that does not
// match is a structural failure (TAMPERED).

// EventHashV2Domain is the domain tag of the v2 audit event serialisation.
const EventHashV2Domain = "lucairn.audit-event/v2\n"

// AuditClaimService and AuditClaimType name the claim that signs an audit
// row's event_hash on every certificate.
const (
	AuditClaimService = anchor.AuditRootSigner
	AuditClaimType    = "EVENTS_RECORDED"
)

// MaxAuditEvents bounds the entries of one audit file (the audit service's
// evidence read refuses a conversation with more than 2,000 counted rows).
const MaxAuditEvents = 20000

// AuditEvent is one entry of audit/events.json.
type AuditEvent struct {
	ConvSeq           uint64
	ConversationID    string
	RequestID         string
	EventID           string
	EventType         string
	SourceService     string
	Actor             string
	PayloadSHA256     string
	PreviousEventHash string
	EventHash         string
	// LeafIndex is the row's position in the whole audit log.
	LeafIndex uint64
	// RootRef is the id of the root (audit/roots.json) the row is proven
	// against; 0 = not anchored yet.
	RootRef uint64
}

// Anchored reports whether the entry names a root.
func (e AuditEvent) Anchored() bool { return e.RootRef != 0 }

// AuditProof is one entry of audit/proofs.json. LeafIndex and TreeSize are
// the proof's own UNSIGNED copies; they are compared, never used.
type AuditProof struct {
	LeafIndex uint64
	TreeSize  uint64
	Path      [][]byte
}

// AuditRootEntry is one entry of audit/roots.json.
type AuditRootEntry struct {
	ID           uint64
	TreeSize     uint64
	RootHash     string
	SigningKeyID string
	Root         anchor.AuditRoot
}

// auditData is the parsed audit/ folder.
type auditData struct {
	events []AuditEvent
	// proofs by conv_seq.
	proofs map[uint64]AuditProof
	// roots in file order, and by id.
	roots []*AuditRootEntry
	byID  map[uint64]*AuditRootEntry
}

// EventHashV2 recomputes a counted audit row's event_hash:
//
//	hex(sha256( previous_event_hash ||
//	            "lucairn.audit-event/v2\n" ||
//	            lp(event_id) lp(event_type) lp(source_service) lp(actor)
//	            lp(payload_sha256) lp(request_id) lp(conversation_id)
//	            lp(decimal(conv_seq)) ))
//
// with lp(s) = decimal(byte length of s) ":" s and no separator between
// fields; previous_event_hash enters as its hex characters. This is the audit
// service's hashchain.ComputeHash(previous, hashchain.SerializeV2(...))
// (dual-sandbox-architecture services/audit/internal/hashchain/v2.go); both
// are gated on the shared golden vectors.
func EventHashV2(e AuditEvent) string {
	h := sha256.New()
	h.Write([]byte(e.PreviousEventHash))
	h.Write([]byte(EventHashV2Domain))
	for _, f := range [...]string{
		e.EventID, e.EventType, e.SourceService, e.Actor,
		e.PayloadSHA256, e.RequestID, e.ConversationID,
		strconv.FormatUint(e.ConvSeq, 10),
	} {
		h.Write([]byte(strconv.Itoa(len(f))))
		h.Write([]byte{':'})
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

var (
	hex64          = regexp.MustCompile(`^[0-9a-f]{64}$`)
	conversationID = regexp.MustCompile(`^[0-9a-f]{32}$`)
	uintLexeme     = regexp.MustCompile(`^(0|[1-9][0-9]{0,18})$`)
)

// maxAuditString bounds every free-text audit field.
const maxAuditString = 512

// jsonObject requires v to be an object with exactly the required keys plus
// any of the optional ones (case-sensitive).
func jsonObject(v any, where string, required []string, optional ...string) (map[string]any, error) {
	o, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s is not a JSON object", where)
	}
	allowed := map[string]bool{}
	for _, k := range required {
		allowed[k] = true
		if _, has := o[k]; !has {
			return nil, fmt.Errorf("%s lacks key %q", where, k)
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	keys := make([]string, 0, len(o))
	for k := range o {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !allowed[k] {
			return nil, fmt.Errorf("%s has key %q, which is not a key of this file (keys are case-sensitive)", where, k)
		}
	}
	return o, nil
}

func jsonString(o map[string]any, where, key string) (string, error) {
	s, ok := o[key].(string)
	if !ok {
		return "", fmt.Errorf("%s %s is not a string", where, key)
	}
	if len(s) > maxAuditString {
		return "", fmt.Errorf("%s %s is longer than %d bytes", where, key, maxAuditString)
	}
	return s, nil
}

func jsonHex64(o map[string]any, where, key string) (string, error) {
	s, _ := o[key].(string)
	if !hex64.MatchString(s) {
		return "", fmt.Errorf("%s %s is not 64 lowercase hex characters", where, key)
	}
	return s, nil
}

// jsonUint reads a JSON integer token (no string, no null, no sign, no
// fraction, no exponent, no leading zero).
func jsonUint(o map[string]any, where, key string) (uint64, error) {
	n, ok := o[key].(json.Number)
	if !ok || !uintLexeme.MatchString(string(n)) {
		return 0, fmt.Errorf("%s %s is not a JSON integer", where, key)
	}
	v, err := strconv.ParseUint(string(n), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s %s is not a JSON integer", where, key)
	}
	return v, nil
}

func jsonBase64(o map[string]any, where, key string) ([]byte, error) {
	s, ok := o[key].(string)
	if !ok || s == "" {
		return nil, fmt.Errorf("%s %s is not a base64 string", where, key)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%s %s is not standard base64", where, key)
	}
	return b, nil
}

// jsonHash32 reads one 32-byte hash in its ONE pinned spelling: exactly 64
// lowercase hex characters (api-contract.md section 2a (b)). Base64 and
// upper-case hex are refused, so a path element has a single spelling.
func jsonHash32(v any) ([]byte, bool) {
	s, _ := v.(string)
	if !hex64.MatchString(s) {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	return b, err == nil && len(b) == sha256.Size
}

// AuditListKeys names, per audit file, the single top-level key that holds
// its array (api-contract.md section 2a (a)).
var AuditListKeys = map[string]string{PathAuditEvents: "events", PathAuditProofs: "proofs", PathAuditRoots: "roots"}

// jsonList reads one audit file in its ONE pinned form: a top-level JSON
// object with exactly the key `key`, whose value is an array. A bare array,
// another or a second key, or a non-array value (null included) is refused.
func jsonList(raw []byte, path, key string) ([]any, error) {
	doc, err := verify.DecodeDocument(raw)
	if err != nil {
		return nil, fmt.Errorf("%s is not one strict JSON document: %s", path, short(err.Error()))
	}
	o, isObject := doc.(map[string]any)
	if _, has := o[key]; !isObject || !has || len(o) != 1 {
		return nil, fmt.Errorf("%s is not a JSON object with the single key %q (a bare array or any other key is not the bundle format)", path, key)
	}
	arr, ok := o[key].([]any)
	if !ok {
		return nil, fmt.Errorf("%s %s is not an array (an empty list is written [])", path, key)
	}
	if len(arr) > MaxAuditEvents {
		return nil, fmt.Errorf("%s holds more than %d entries", path, MaxAuditEvents)
	}
	return arr, nil
}

var (
	auditEventKeys = []string{"conv_seq", "conversation_id", "request_id", "event_id", "event_type", "source_service", "actor",
		"payload_sha256", "previous_event_hash", "event_hash", "leaf_index", "root_ref"}
	auditProofKeys = []string{"conv_seq", "leaf_index", "tree_size", "path"}
	auditRootKeys  = []string{"id", "tree_size", "root_hash", "root_artifact", "root_signature", "signing_key_id", "rekor_entry"}
	auditRekorKeys = []string{"log_index", "integrated_time", "canonical_body", "signed_entry_timestamp", "inclusion_proof"}
)

// parseAudit reads the three audit files. An error is a file that does not
// have the documented shape: no audit check can run on it. refProblems are
// broken references BETWEEN well-formed files (a proof for a row that is not
// listed, a row naming a root that is not there): they fail the audit-files
// step, and the other checks still run, so that a removed row is reported as
// the gap it is and not only as a dangling proof. The checks that carry
// evidence are in auditVerifier.
func parseAudit(files map[string][]byte) (d *auditData, refProblems []string, err error) {
	d, err = parseAuditFiles(files)
	if err != nil {
		return nil, nil, err
	}
	return d, auditReferenceProblems(d), nil
}

func parseAuditFiles(files map[string][]byte) (*auditData, error) {
	d := &auditData{proofs: map[uint64]AuditProof{}, byID: map[uint64]*AuditRootEntry{}}

	evs, err := jsonList(files[PathAuditEvents], PathAuditEvents, AuditListKeys[PathAuditEvents])
	if err != nil {
		return nil, err
	}
	seenReq, seenID, seenHash := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, raw := range evs {
		where := fmt.Sprintf("%s entry %d", PathAuditEvents, i)
		o, err := jsonObject(raw, where, auditEventKeys, "recorded_at")
		if err != nil {
			return nil, err
		}
		var e AuditEvent
		if e.ConvSeq, err = jsonUint(o, where, "conv_seq"); err != nil {
			return nil, err
		}
		if e.ConvSeq == 0 {
			return nil, fmt.Errorf("%s conv_seq is 0 (the counter starts at 1)", where)
		}
		for _, f := range []struct {
			key string
			dst *string
		}{{"conversation_id", &e.ConversationID}, {"request_id", &e.RequestID}, {"event_id", &e.EventID},
			{"event_type", &e.EventType}, {"source_service", &e.SourceService}, {"actor", &e.Actor}} {
			if *f.dst, err = jsonString(o, where, f.key); err != nil {
				return nil, err
			}
		}
		if !conversationID.MatchString(e.ConversationID) {
			return nil, fmt.Errorf("%s conversation_id is not 32 lowercase hex characters", where)
		}
		if e.EventID == "" || e.EventType == "" {
			return nil, fmt.Errorf("%s lacks an event_id or event_type", where)
		}
		if e.PayloadSHA256, err = jsonHex64(o, where, "payload_sha256"); err != nil {
			return nil, err
		}
		if e.EventHash, err = jsonHex64(o, where, "event_hash"); err != nil {
			return nil, err
		}
		if s, isStr := o["previous_event_hash"].(string); isStr && s == "" {
			e.PreviousEventHash = ""
		} else if e.PreviousEventHash, err = jsonHex64(o, where, "previous_event_hash"); err != nil {
			return nil, err
		}
		if e.LeafIndex, err = jsonUint(o, where, "leaf_index"); err != nil {
			return nil, err
		}
		if e.RootRef, err = jsonUint(o, where, "root_ref"); err != nil {
			return nil, err
		}
		if _, has := o["recorded_at"]; has {
			if _, err := jsonString(o, where, "recorded_at"); err != nil {
				return nil, err
			}
		}
		// One counted (terminal) event per request. An entry without a
		// request id belongs to no certificate; it is reported as such.
		if (e.RequestID != "" && seenReq[e.RequestID]) || seenID[e.EventID] || seenHash[e.EventHash] {
			return nil, fmt.Errorf("%s repeats a request_id, event_id or event_hash of an earlier entry (one counted event per request)", where)
		}
		seenReq[e.RequestID], seenID[e.EventID], seenHash[e.EventHash] = true, true, true
		d.events = append(d.events, e)
	}

	prs, err := jsonList(files[PathAuditProofs], PathAuditProofs, AuditListKeys[PathAuditProofs])
	if err != nil {
		return nil, err
	}
	for i, raw := range prs {
		where := fmt.Sprintf("%s entry %d", PathAuditProofs, i)
		o, err := jsonObject(raw, where, auditProofKeys)
		if err != nil {
			return nil, err
		}
		seq, err := jsonUint(o, where, "conv_seq")
		if err != nil {
			return nil, err
		}
		var p AuditProof
		if p.LeafIndex, err = jsonUint(o, where, "leaf_index"); err != nil {
			return nil, err
		}
		if p.TreeSize, err = jsonUint(o, where, "tree_size"); err != nil {
			return nil, err
		}
		arr, ok := o["path"].([]any)
		if !ok || len(arr) > anchor.MaxAuditProofHashes {
			return nil, fmt.Errorf("%s path is not an array of at most %d hashes", where, anchor.MaxAuditProofHashes)
		}
		p.Path = make([][]byte, len(arr))
		for j, h := range arr {
			if p.Path[j], ok = jsonHash32(h); !ok {
				return nil, fmt.Errorf("%s path element %d is not a 32-byte hash written as 64 lowercase hex characters", where, j)
			}
		}
		if _, dup := d.proofs[seq]; dup {
			return nil, fmt.Errorf("%s: a second proof for conv_seq %d", where, seq)
		}
		d.proofs[seq] = p
	}

	rts, err := jsonList(files[PathAuditRoots], PathAuditRoots, AuditListKeys[PathAuditRoots])
	if err != nil {
		return nil, err
	}
	for i, raw := range rts {
		where := fmt.Sprintf("%s entry %d", PathAuditRoots, i)
		o, err := jsonObject(raw, where, auditRootKeys, "published_at")
		if err != nil {
			return nil, err
		}
		r := &AuditRootEntry{}
		if r.ID, err = jsonUint(o, where, "id"); err != nil {
			return nil, err
		}
		if r.TreeSize, err = jsonUint(o, where, "tree_size"); err != nil {
			return nil, err
		}
		if r.ID == 0 || r.TreeSize == 0 {
			return nil, fmt.Errorf("%s id or tree_size is 0", where)
		}
		if r.RootHash, err = jsonHex64(o, where, "root_hash"); err != nil {
			return nil, err
		}
		if r.Root.Artifact, err = jsonBase64(o, where, "root_artifact"); err != nil {
			return nil, err
		}
		if r.Root.Signature, err = jsonBase64(o, where, "root_signature"); err != nil {
			return nil, err
		}
		if r.SigningKeyID, err = jsonString(o, where, "signing_key_id"); err != nil {
			return nil, err
		}
		rw := where + " rekor_entry"
		ro, err := jsonObject(o["rekor_entry"], rw, auditRekorKeys, "log_url", "uuid", "log_id")
		if err != nil {
			return nil, err
		}
		idx, err := jsonUint(ro, rw, "log_index")
		if err != nil {
			return nil, err
		}
		itime, err := jsonUint(ro, rw, "integrated_time")
		if err != nil {
			return nil, err
		}
		if idx > 1<<62 || itime == 0 || itime > 1<<40 {
			return nil, fmt.Errorf("%s log_index or integrated_time is out of range", rw)
		}
		r.Root.Entry.LogIndex, r.Root.Entry.IntegratedTime = int64(idx), int64(itime)
		if r.Root.Entry.CanonicalBody, err = jsonBase64(ro, rw, "canonical_body"); err != nil {
			return nil, err
		}
		if r.Root.Entry.SignedEntryTimestamp, err = jsonBase64(ro, rw, "signed_entry_timestamp"); err != nil {
			return nil, err
		}
		if r.Root.Entry.InclusionProof, err = jsonBase64(ro, rw, "inclusion_proof"); err != nil {
			return nil, err
		}
		for _, k := range []string{"log_url", "uuid", "log_id"} {
			if _, has := ro[k]; has {
				if _, err := jsonString(ro, rw, k); err != nil {
					return nil, err
				}
			}
		}
		if _, has := o["published_at"]; has {
			if _, err := jsonString(o, where, "published_at"); err != nil {
				return nil, err
			}
		}
		if _, dup := d.byID[r.ID]; dup {
			return nil, fmt.Errorf("%s: a second root with id %d", where, r.ID)
		}
		d.byID[r.ID] = r
		d.roots = append(d.roots, r)
	}
	return d, nil
}

// noProof reports the explicit "no proof" form of a proofs.json entry.
func (p AuditProof) noProof() bool { return p.TreeSize == 0 && len(p.Path) == 0 }

// auditReferenceProblems lists broken references between the three files.
func auditReferenceProblems(d *auditData) []string {
	var out []string
	bySeq := map[uint64]bool{}
	for _, e := range d.events {
		// A repeated conv_seq is the continuity check's finding ("duplicate
		// seq"); only the first entry of a number is linked here.
		if bySeq[e.ConvSeq] {
			continue
		}
		bySeq[e.ConvSeq] = true
		p, hasProof := d.proofs[e.ConvSeq]
		switch {
		case e.Anchored() && (!hasProof || p.noProof()):
			out = append(out, fmt.Sprintf("seq %d names root %d but %s has no proof for it", e.ConvSeq, e.RootRef, PathAuditProofs))
		case !e.Anchored() && hasProof && !p.noProof():
			out = append(out, fmt.Sprintf("%s holds a proof for seq %d, which names no root", PathAuditProofs, e.ConvSeq))
		}
		if e.Anchored() && d.byID[e.RootRef] == nil {
			out = append(out, fmt.Sprintf("seq %d names root %d, which is not in %s", e.ConvSeq, e.RootRef, PathAuditRoots))
		}
	}
	for seq := range d.proofs {
		if !bySeq[seq] {
			out = append(out, fmt.Sprintf("%s holds a proof for seq %d, which is not in %s", PathAuditProofs, seq, PathAuditEvents))
		}
	}
	sort.Strings(out)
	return out
}

// auditClaim is one audit-signed EVENTS_RECORDED claim of a certificate, read
// from its verified, signed bytes only.
type auditClaim struct {
	// requestID is the claim's own signed request_id.
	requestID                                    string
	eventHash, eventID, eventType, sourceService string
	// D3: the claim of a COUNTED request also signs the counter
	// (conversation_id + conv_seq). hasSeq is the "counted" marker.
	conversationID string
	hasSeq         bool
	seq            uint64
	// seqMalformed: a conv_seq key that is not a positive integer.
	seqMalformed bool
}

// auditClaimsOf collects the dsa-audit EVENTS_RECORDED claims out of a
// verified chain result's claims (key "<index>:<service_id>:<claim_type>").
func auditClaimsOf(claims map[string]map[string]any) []auditClaim {
	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []auditClaim
	for _, k := range keys {
		first, last := strings.Index(k, ":"), strings.LastIndex(k, ":")
		if first < 0 || last <= first || k[first+1:last] != AuditClaimService || k[last+1:] != AuditClaimType {
			continue
		}
		v := claims[k]
		c := auditClaim{
			requestID: str(v["/request_id"]),
			eventHash: str(v["/payload/event_hash"]), eventID: str(v["/payload/event_id"]),
			eventType: str(v["/payload/event_type"]), sourceService: str(v["/payload/source_service"]),
			conversationID: str(v["/payload/conversation_id"]),
		}
		if raw, has := v["/payload/conv_seq"]; has {
			lex := ""
			switch x := raw.(type) {
			case json.Number:
				lex = string(x)
			case string:
				lex = x
			}
			n, err := strconv.ParseUint(lex, 10, 64)
			if !uintLexeme.MatchString(lex) || err != nil || n == 0 {
				c.seqMalformed = true
			} else {
				c.hasSeq, c.seq = true, n
			}
		}
		out = append(out, c)
	}
	return out
}

// certAudit is what one certificate contributes to the counter checks.
type certAudit struct {
	// claimsVerified: the claim chain verified, so claims is authoritative
	// (an empty list then means "no audit claim on this certificate").
	claimsVerified bool
	claims         []auditClaim
	// These are separate decisions: signed facts require an entry even when
	// the label-sensitive tier makes this certificate ineligible for acceptance.
	cleaningRequiredFrom  time.Time
	cleaningBeforeStart   bool
	needsCleaningEntry    bool
	cleaningStepEligible  bool
	gatewayConversationID string
}

// countedSeq returns the conv_seq a signed claim states, if any.
func (c certAudit) countedSeq() (uint64, bool) {
	for _, a := range c.claims {
		if a.hasSeq {
			return a.seq, true
		}
	}
	return 0, false
}

// errNoAuditKey marks a deployment whose trust roots pin no dsa-audit key.
var errNoAuditKey = errors.New("no " + anchor.AuditRootSigner + " key pinned (pass --service-key " + anchor.AuditRootSigner + "=BASE64)")
