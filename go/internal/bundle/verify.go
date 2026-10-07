package bundle

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	lucairn "github.com/declade/lucairn-sdks/go"
	"github.com/declade/lucairn-sdks/go/internal/anchor"
	"github.com/declade/lucairn-sdks/go/internal/verify"
)

// RekorFetcher re-fetches a log entry by global index (the --online mode).
type RekorFetcher interface {
	Fetch(logIndex int64) (*FetchedEntry, error)
}

// FetchedEntry is one entry as the log serves it now.
type FetchedEntry struct {
	Body                 []byte
	IntegratedTime       int64
	LogIndex             int64
	SignedEntryTimestamp []byte
	InclusionProof       []byte
}

// Options configure one verification run.
type Options struct {
	Roots TrustRoots
	// Now is "now" for certificate validity checks; zero = time.Now().
	Now time.Time
	// Fetcher, when non-nil, enables the online Rekor re-fetch.
	Fetcher RekorFetcher
}

// Verify checks one bundle. It never returns an error: every problem is a
// step in the report, and the report's verdict decides the exit code.
func Verify(name string, data []byte, opt Options) *Report {
	if opt.Now.IsZero() {
		opt.Now = time.Now()
	}
	r := &Report{Bundle: name, TrustRoots: opt.Roots.Label, Online: opt.Fetcher != nil, NotCovered: NotCoveredV1, anchorsNotRequired: !opt.Roots.RequireAnchors}
	defer r.finish()

	files, ok := readZip(r, data)
	if !ok {
		return r
	}
	m, ok := readManifest(r, files)
	if !ok {
		return r
	}
	r.ConversationID = m.ConversationID
	withAudit := m.FormatVersion == FormatVersionAudit
	if withAudit {
		r.BundleFormat, r.NotCovered, r.auditChecked = FormatVersionAudit, NotCoveredV2, true
	}
	if !checkFiles(r, m, files) {
		return r
	}
	certs, ok := checkCertificateList(r, m, files)
	if !ok {
		return r
	}
	r.Certificates = len(certs)

	digests := map[string]string{}
	for _, c := range certs {
		s := sha256.Sum256(files[c.Path])
		digests[c.RequestID] = hex.EncodeToString(s[:])
	}
	r.CertificatesDigest = CertificatesDigest(digests)
	if m.CertificatesDigest != r.CertificatesDigest {
		r.add("bundle", "certificate-set", Fail, "manifest certificates_digest does not match the certificate files")
	} else {
		r.add("bundle", "certificate-set", Pass, r.CertificatesDigest)
	}

	if m.Completeness.Listing == ListingExhausted && withAudit {
		r.skip("bundle", "completeness", "the exporter states (unsigned) that its certificate listing for this conversation ran to its end; whether a request is missing is what the audit-* steps check", false)
	} else if m.Completeness.Listing == ListingExhausted {
		r.skip("bundle", "completeness", "not provable in this bundle version; the exporter states (unsigned) that its certificate listing for this conversation ran to its end", false)
	} else {
		r.skip("bundle", "completeness", "the exporter's certificate listing did not run to its end: "+short(m.Completeness.Listing+" "+m.Completeness.Note), true)
	}

	v := &certVerifier{r: r, m: m, opt: opt, seenTSA: map[string]string{}, seenRekor: map[string]string{}, seenBody: map[string]string{}}
	// Format 2: the audit/ folder (per-conversation counter, inclusion proofs,
	// anchored roots). The checks that need no certificate run first.
	var av *auditVerifier
	if withAudit {
		av = newAuditVerifier(r, m, files, opt)
	}
	for _, c := range certs {
		ca, si := v.verify(c, files[c.Path])
		// Reuse the binding guard's authenticated issued_at; zero is strict.
		ca.cleaningRequiredFrom = opt.Roots.CleaningRequiredFrom
		ca.cleaningBeforeStart = !ca.cleaningRequiredFrom.IsZero() && !si.issuedAt.IsZero() && si.issuedAt.Before(ca.cleaningRequiredFrom)
		if ca.needsCleaningEntry {
			r.hasCleaningSteps = true
		}
		if av != nil {
			av.cert(c.RequestID, ca, si.issuedAt)
		} else {
			// Format 1 has no counter. Cleaning steps and certificates whose
			// signed audit claims say they were counted still need entries
			// (including a format-2 bundle downgraded to format 1).
			noCounterEntry(r, c.RequestID, ca, false)
		}
	}
	if av != nil {
		av.finish()
	} else {
		r.skip("bundle", "audit-counter", "not in this bundle version", false)
		r.skip("bundle", "audit-inclusion", "not in this bundle version", false)
	}
	r.skip("bundle", "report-content", "reports, verification.json and README.txt are not authenticated: the manifest is unsigned (see LIMITATION)", false)
	r.reportUnauthenticated = true
	if _, has := files[PathVerification]; has {
		r.skip("bundle", "verification.json", "informational export-time record; never used as evidence", false)
	}
	return r
}

func readZip(r *Report, data []byte) (map[string][]byte, bool) {
	if len(data) > MaxBundleBytes {
		r.skip("bundle", "structure", fmt.Sprintf("bundle larger than %d bytes", MaxBundleBytes), true)
		return nil, false
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if errors.Is(err, zip.ErrInsecurePath) {
		r.add("bundle", "structure", Fail, "the zip holds an entry with an unsafe path")
		return nil, false
	}
	if err != nil {
		r.skip("bundle", "structure", "not a readable zip file: "+short(err.Error()), true)
		return nil, false
	}
	if len(zr.File) > MaxFiles {
		r.add("bundle", "structure", Fail, "too many entries")
		return nil, false
	}
	// Which layout applies is the manifest's format_version (the full manifest
	// check below reads the same value). Anything but a readable "2" keeps the
	// v1 layout, so a v1 bundle is checked exactly as before.
	version := sniffFormatVersion(zr)
	files := map[string][]byte{}
	var total int64
	// No entry is skipped before these checks: a directory entry (any name
	// ending in "/", e.g. "../../outside/") is not a bundle path and fails here.
	for _, f := range zr.File {
		if !AllowedPathIn(version, f.Name) {
			r.add("bundle", "structure", Fail, fmt.Sprintf("file %q is not part of the v%d bundle format", f.Name, version))
			return nil, false
		}
		if f.Mode()&^0o777 != 0 && !f.Mode().IsRegular() {
			r.add("bundle", "structure", Fail, fmt.Sprintf("entry %q is not a regular file", f.Name))
			return nil, false
		}
		if _, dup := files[f.Name]; dup {
			r.add("bundle", "structure", Fail, fmt.Sprintf("file %q appears twice", f.Name))
			return nil, false
		}
		if f.UncompressedSize64 > MaxFileBytes {
			r.add("bundle", "structure", Fail, fmt.Sprintf("file %q is larger than %d bytes", f.Name, MaxFileBytes))
			return nil, false
		}
		rc, err := f.Open()
		if err != nil {
			r.add("bundle", "structure", Fail, fmt.Sprintf("file %q does not open: %s", f.Name, short(err.Error())))
			return nil, false
		}
		b, err := io.ReadAll(io.LimitReader(rc, MaxFileBytes+1))
		rc.Close()
		if err != nil || int64(len(b)) > MaxFileBytes {
			r.add("bundle", "structure", Fail, fmt.Sprintf("file %q does not read cleanly", f.Name))
			return nil, false
		}
		total += int64(len(b))
		if total > MaxBundleBytes {
			r.add("bundle", "structure", Fail, "bundle content exceeds the size bound")
			return nil, false
		}
		files[f.Name] = b
	}
	r.add("bundle", "structure", Pass, fmt.Sprintf("%d files, all in the v%d layout", len(files), version))
	return files, true
}

// sniffFormatVersion reads manifest.json's format_version ahead of the entry
// loop, only to pick the path allowlist: FormatVersionAudit when the manifest
// is one strict JSON object naming this format and version 2, otherwise
// FormatVersion (1). It validates nothing — every entry, the manifest
// included, still goes through the full checks.
func sniffFormatVersion(zr *zip.Reader) int {
	for _, f := range zr.File {
		if f.Name != PathManifest {
			continue
		}
		if f.UncompressedSize64 > MaxFileBytes {
			return FormatVersion
		}
		rc, err := f.Open()
		if err != nil {
			return FormatVersion
		}
		b, err := io.ReadAll(io.LimitReader(rc, MaxFileBytes+1))
		rc.Close()
		if err != nil || int64(len(b)) > MaxFileBytes {
			return FormatVersion
		}
		doc, err := verify.DecodeDocument(b)
		gm, isObj := doc.(map[string]any)
		if err != nil || !isObj || gm["format"] != FormatName {
			return FormatVersion
		}
		if n, _ := gm["format_version"].(json.Number); string(n) == strconv.Itoa(FormatVersionAudit) {
			return FormatVersionAudit
		}
		return FormatVersion
	}
	return FormatVersion
}

func readManifest(r *Report, files map[string][]byte) (*Manifest, bool) {
	raw, ok := files[PathManifest]
	if !ok {
		r.add("bundle", "manifest", Fail, "required file manifest.json is missing")
		return nil, false
	}
	generic, err := verify.DecodeDocument(raw)
	if err != nil {
		r.add("bundle", "manifest", Fail, "manifest.json is not one strict JSON document: "+short(err.Error()))
		return nil, false
	}
	gm, isObj := generic.(map[string]any)
	if !isObj {
		r.add("bundle", "manifest", Fail, "manifest.json is not a JSON object")
		return nil, false
	}
	if p := manifestKeyProblem(gm); p != "" {
		r.add("bundle", "manifest", Fail, p)
		return nil, false
	}
	if gm["format"] != FormatName {
		r.skip("bundle", "manifest", fmt.Sprintf("unknown bundle format %v", gm["format"]), true)
		return nil, false
	}
	version := 0
	switch n, _ := gm["format_version"].(json.Number); string(n) {
	case strconv.Itoa(FormatVersion):
		version = FormatVersion
	case strconv.Itoa(FormatVersionAudit):
		version = FormatVersionAudit
	default:
		r.skip("bundle", "manifest", fmt.Sprintf("bundle format_version %v is not supported by this tool (supports %d and %d); use a newer lucairn-bundle-verify", gm["format_version"], FormatVersion, FormatVersionAudit), true)
		return nil, false
	}
	var m Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil || m.FormatVersion != version {
		msg := "format_version does not decode"
		if err != nil {
			msg = short(err.Error())
		}
		r.add("bundle", "manifest", Fail, fmt.Sprintf("manifest.json does not match the v%d schema: %s", version, msg))
		return nil, false
	}
	if m.BundleKind != KindConversation || m.ConversationID == "" {
		r.add("bundle", "manifest", Fail, "manifest must name bundle_kind \"conversation\" and a conversation_id")
		return nil, false
	}
	return &m, true
}

func checkFiles(r *Report, m *Manifest, files map[string][]byte) bool {
	listed := map[string]bool{}
	var problems []string
	for _, p := range RequiredPathsIn(m.FormatVersion) {
		if _, ok := files[p]; !ok {
			problems = append(problems, fmt.Sprintf("required file %q is missing", p))
		}
	}
	for _, f := range m.Files {
		if f.Path == PathManifest || !AllowedPathIn(m.FormatVersion, f.Path) {
			problems = append(problems, fmt.Sprintf("manifest lists a path that cannot be in a v%d bundle: %q", m.FormatVersion, f.Path))
			continue
		}
		if listed[f.Path] {
			problems = append(problems, fmt.Sprintf("manifest lists %q twice", f.Path))
			continue
		}
		listed[f.Path] = true
		b, ok := files[f.Path]
		if !ok {
			problems = append(problems, fmt.Sprintf("listed file %q is missing", f.Path))
			continue
		}
		s := sha256.Sum256(b)
		if !strings.EqualFold(hex.EncodeToString(s[:]), f.SHA256) || int64(len(b)) != f.Size {
			problems = append(problems, fmt.Sprintf("file %q does not match its manifest digest", f.Path))
		}
	}
	for p := range files {
		if p != PathManifest && !listed[p] {
			problems = append(problems, fmt.Sprintf("file %q is not listed in the manifest", p))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		r.add("bundle", "manifest", Fail, strings.Join(problems, "; "))
		return false
	}
	r.add("bundle", "manifest", Pass, fmt.Sprintf("every file matches its SHA-256 (%d files); no unlisted file", len(m.Files)))
	return true
}

func checkCertificateList(r *Report, m *Manifest, files map[string][]byte) ([]ManifestCert, bool) {
	seenPath, seenReq := map[string]bool{}, map[string]bool{}
	var problems []string
	for _, c := range m.Certificates {
		if !strings.HasPrefix(c.Path, DirCertificates) || !AllowedPath(c.Path) {
			problems = append(problems, fmt.Sprintf("certificate entry path %q is not under certificates/", c.Path))
			continue
		}
		if c.RequestID == "" || c.CertificateID == "" {
			problems = append(problems, fmt.Sprintf("certificate entry %q lacks request_id or certificate_id", c.Path))
			continue
		}
		if seenPath[c.Path] || seenReq[c.RequestID] {
			problems = append(problems, fmt.Sprintf("certificate %q / request %q listed twice", c.Path, c.RequestID))
			continue
		}
		seenPath[c.Path], seenReq[c.RequestID] = true, true
		if _, ok := files[c.Path]; !ok {
			problems = append(problems, fmt.Sprintf("certificate file %q is missing", c.Path))
		}
	}
	for p := range files {
		if strings.HasPrefix(p, DirCertificates) && !seenPath[p] {
			problems = append(problems, fmt.Sprintf("certificate file %q has no certificate entry", p))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		r.add("bundle", "certificate-list", Fail, strings.Join(problems, "; "))
		return nil, false
	}
	if len(m.Certificates) == 0 {
		r.add("bundle", "certificate-list", Fail, fmt.Sprintf("the bundle contains no certificate (a v%d bundle holds at least one)", m.FormatVersion))
		return nil, false
	}
	r.add("bundle", "certificate-list", Pass, fmt.Sprintf("%d certificates, one file each", len(m.Certificates)))
	return m.Certificates, true
}

type certVerifier struct {
	r         *Report
	m         *Manifest
	opt       Options
	seenTSA   map[string]string
	seenRekor map[string]string
	seenBody  map[string]string
}

// verify checks one certificate. It returns what the audit counter checks
// need from it: its audit-signed claims (from verified, signed bytes only)
// and the signed input (signed issued_at).
func (v *certVerifier) verify(mc ManifestCert, raw []byte) (certAudit, signedInput) {
	scope := mc.RequestID
	r := v.r
	doc, err := verify.DecodeCertificate(raw)
	cm, isObj := doc.(map[string]any)
	if err != nil || !isObj {
		r.add(scope, "signature", Fail, "certificate is not one strict JSON object")
		return certAudit{}, signedInput{}
	}
	wkid, _ := cm["witness_key_id"].(string)
	wkey, haveKey := v.opt.Roots.WitnessKeys[wkid]
	var si signedInput
	var ca certAudit
	if !haveKey {
		r.skip(scope, "signature", fmt.Sprintf("no pinned key for witness key id %q (pass --witness-key)", wkid), true)
	} else {
		si, ca = v.signature(scope, mc, raw, wkid, wkey)
	}

	issuedAt, _ := time.Parse(time.RFC3339Nano, str(cm["issued_at"]))
	anchorClaimed := anchorStatusClaimsAnchored(cm)
	att, _ := cm["attestation"].(map[string]any)
	cb := v.bindingOf(att, si)
	v.timestamp(scope, cm, att, issuedAt, anchorClaimed, cb)
	if haveKey {
		v.rekor(scope, att, issuedAt, anchorClaimed, wkey, cb)
	} else {
		r.skip(scope, "rekor", "no pinned witness key to check the entry's author against", true)
	}
	return ca, si
}

// signedInput is what a verified witness signature authenticates and the
// anchor-binding check needs: the exact signed canonical bytes and the signed
// issued_at. Zero value = the signature was not verified.
type signedInput struct {
	signable []byte
	issuedAt time.Time
}

func (v *certVerifier) signature(scope string, mc ManifestCert, raw []byte, wkid string, wkey ed25519.PublicKey) (signedInput, certAudit) {
	r := v.r
	res, err := lucairn.VerifyCertificate(raw, lucairn.VerifyCertificateKeys{WitnessKeyID: wkid, WitnessPublicKey: []byte(wkey)})
	if err != nil {
		r.add(scope, "signature", Fail, "witness signature: "+short(err.Error()))
		return signedInput{}, certAudit{}
	}
	if res.RequestID != mc.RequestID || res.CertificateID != mc.CertificateID {
		r.add(scope, "signature", Fail, "the signed request/certificate id is not the one the manifest lists for this file")
		return signedInput{}, certAudit{}
	}
	r.add(scope, "signature", Pass, fmt.Sprintf("witness %s signature (%s) over %s", wkid, res.SignableVersion, res.CertificateID))
	si := signedBytesOfFn(raw, wkid, wkey, res.CertificateID)
	if si.issuedAt.IsZero() && !v.opt.Roots.BindingRequiredAfter.IsZero() {
		// The signature verified, but its signed bytes / signed issued_at
		// could not be recovered a second time. Without them the downgrade
		// guard cannot decide whether this certificate must be content-bound,
		// so it must not switch off silently (ToB #77 I2).
		r.skip(scope, "anchor-binding", "the signed issued_at could not be recovered after the signature check, so the anchor-binding cutover ("+
			v.opt.Roots.BindingRequiredAfter.Format(time.RFC3339)+") cannot be applied to this certificate", true)
	}
	return si, v.claimChain(scope, mc, raw, wkid, wkey)
}

// signedBytesOfFn is signedBytesOf; a variable so a test can make the second
// pipeline run fail after the signature passed (ToB #77 I2).
var signedBytesOfFn = signedBytesOf

// signedBytesOf re-runs the SDK's signature pipeline to obtain the exact
// bytes the (already verified) witness signature covers, and the signed
// issued_at. The same pipeline, the same input: if it does not verify again
// identically, the binding inputs are withheld (zero value).
func signedBytesOf(raw []byte, wkid string, wkey ed25519.PublicKey, certID string) signedInput {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return signedInput{}
	}
	res, err := verify.Run(doc, wkid, []byte(wkey), verify.RunOptions{})
	if err != nil || res.CertificateID != certID || len(res.SignedBytes) == 0 {
		return signedInput{}
	}
	at, err := time.Parse(time.RFC3339Nano, res.IssuedAtISO)
	if err != nil {
		return signedInput{}
	}
	return signedInput{signable: res.SignedBytes, issuedAt: at.UTC()}
}

// claimChain verifies every claim signature. The returned certAudit carries
// the certificate's audit-signed EVENTS_RECORDED claims and cleaning-step
// inputs when (and only when) the chain verified.
func (v *certVerifier) claimChain(scope string, mc ManifestCert, raw []byte, wkid string, wkey ed25519.PublicKey) certAudit {
	r := v.r

	if len(v.opt.Roots.ServiceKeys) == 0 {
		r.skip(scope, "claims", "no service keys pinned for this deployment (pass --service-key)", true)
		r.skip(scope, "binding", "claim signatures not checked", true)
		return certAudit{}
	}
	svc := map[string]any{}
	for id, k := range v.opt.Roots.ServiceKeys {
		svc[id] = []byte(k)
	}
	rid, cid := mc.RequestID, mc.CertificateID
	ch, err := lucairn.VerifyCertificateChain(raw, lucairn.CertificateChainKeys{
		WitnessKeyID: wkid, WitnessPublicKey: []byte(wkey), ServicePublicKeys: svc,
		ExpectedRequestID: &rid, ExpectedCertificateID: &cid,
	})
	if err != nil {
		r.skip(scope, "claims", "pinned keys refused: "+short(err.Error()), true)
		r.skip(scope, "binding", "claim signatures not checked", true)
		return certAudit{}
	}
	if ch.Verdict == "FAILED" {
		if ch.Reason == "sealed_failed" {
			r.skip(scope, "claims", "the witness sealed this certificate with verdict FAILED, so the claim check does not run", true)
			r.skip(scope, "binding", "claim signatures not checked", true)
			return certAudit{}
		}
		r.add(scope, "claims", Fail, "claim chain: "+ch.Reason)
		return certAudit{}
	}
	r.add(scope, "claims", Pass, "every claim signature verifies under its pinned service key")
	verdictNote := "what this certificate itself attests"
	if ch.Verdict != "VERIFIED" {
		verdictNote += "; a VALID bundle does not make it VERIFIED"
	}
	r.info(scope, "chain-verdict", fmt.Sprintf("%s (%s; signed tier %s) - %s", ch.Verdict, ch.Reason, ch.SignedCertTier, verdictNote))
	r.info(scope, "user-unredacted", ch.UserUnredacted+userUnredactedNote(ch.UserUnredacted))
	v.binding(scope, ch)
	values := map[string]map[string]any{}
	for k, c := range ch.Verified.Claims {
		values[k] = c.Values
	}
	ca := certAudit{claimsVerified: true, claims: auditClaimsOf(values)}
	gateway, sanitizer, other := 0, 0, 0
	marker := false
	for _, c := range values {
		switch str(c["/service_id"]) {
		case "dsa-gateway":
			gateway++
			marker = marker || str(c["/payload/cert_tier"]) == "input-shield"
			ca.gatewayConversationID = str(c["/payload/conversation_id"])
		case "dsa-sanitizer":
			sanitizer++
		default:
			other++
		}
	}
	// Requirement: only authenticated marker/topology, never the unsigned
	// label, sealed verdict, or the label-sensitive SignedCertTier result.
	ca.needsCleaningEntry = marker || (gateway >= 1 && sanitizer >= 1 && other == 0)
	// Eligibility is deliberately stricter. Entry matching and all shared
	// hash/continuity/inclusion checks still have to pass in auditVerifier.cert.
	ca.cleaningStepEligible = ch.SignedCertTier == verify.ChainTierInputShieldTwoSigner &&
		len(values) == 2 && gateway == 1 && sanitizer == 1
	return ca
}

// binding checks the SIGNED conversation and customer ids in the claim
// payloads against the manifest.
func (v *certVerifier) binding(scope string, ch *lucairn.CertificateChainResult) {
	r := v.r
	var convs, custs []string
	for _, c := range ch.Verified.Claims {
		if s, ok := c.Values["/payload/conversation_id"].(string); ok && s != "" {
			convs = append(convs, s)
		}
		if s, ok := c.Values["/payload/customer_id"].(string); ok && s != "" {
			custs = append(custs, s)
		}
	}
	for _, s := range convs {
		if s != v.m.ConversationID {
			r.add(scope, "binding", Fail, "a signed claim names a different conversation than this bundle (certificate from another conversation)")
			return
		}
	}
	for _, s := range custs {
		if v.m.CustomerID == "" || s != v.m.CustomerID {
			r.add(scope, "binding", Fail, "a signed claim names a different customer than this bundle")
			return
		}
	}
	switch {
	case len(convs) == 0:
		r.skip(scope, "binding", "no signed claim carries a conversation id, so membership in this conversation cannot be shown", true)
	case len(custs) == 0:
		r.skip(scope, "binding", "no signed claim carries a customer id", true)
	default:
		r.add(scope, "binding", Pass, "signed claims name this conversation and this customer")
	}
}

func userUnredactedNote(u string) string {
	switch u {
	case "true":
		return " - the user chose to send this message unredacted"
	case "false":
		return ""
	}
	return " - not stated by a signed claim"
}

// bindingForm is the anchor form a certificate's timestamp declares on
// attestation.timestamp.hash_algorithm (unsigned).
type bindingForm int

const (
	formLegacy  bindingForm = iota // "" / SHA-256: imprint = recorded cert_hash
	formV1                         // anchor.HashAlgorithmV1
	formUnknown                    // anything else
)

// certBinding is everything the anchor steps need to decide content binding.
type certBinding struct {
	form   bindingForm
	marker string
	// h is the binding-v1 digest recomputed from the recorded cert_hash and
	// the signature-verified signable; nil when either is unavailable.
	h []byte
	// certHash is the recorded cert_hash when it is 32 bytes, else nil.
	certHash []byte
	// required: the downgrade guard applies (signed issued_at after
	// Roots.BindingRequiredAfter), so only binding-v1 anchors can pass.
	required       bool
	signedIssuedAt time.Time
}

func (v *certVerifier) bindingOf(att map[string]any, si signedInput) certBinding {
	ts, _ := att["timestamp"].(map[string]any)
	cb := certBinding{form: formLegacy, signedIssuedAt: si.issuedAt}
	if raw, present := ts["hash_algorithm"]; present && raw != nil {
		m, isStr := raw.(string)
		cb.marker = m
		switch {
		case !isStr:
			cb.form, cb.marker = formUnknown, fmt.Sprint(raw)
		case m == anchor.HashAlgorithmV1:
			cb.form = formV1
		case m == "" || m == anchor.HashAlgorithmLegacy:
			// Exactly the witness's anchorbinding.FormOf: "" and "SHA-256"
			// are legacy; every other spelling is unknown (TAMPERED).
			cb.form = formLegacy
		default:
			cb.form = formUnknown
		}
	}
	if certHash, ok := b64(ts["cert_hash"]); ok && len(certHash) == sha256.Size {
		cb.certHash = certHash
		if len(si.signable) > 0 {
			cb.h = anchor.DigestV1(certHash, si.signable)
		}
	}
	cut := v.opt.Roots.BindingRequiredAfter
	cb.required = !cut.IsZero() && !si.issuedAt.IsZero() && si.issuedAt.After(cut)
	return cb
}

// bindingProblem is the FAIL reason shared by both anchor steps when the
// declared form cannot pass: an unknown marker, or a certificate issued after
// the cutover whose anchors are not binding v1 (marker stripped or anchors
// from another certificate).
func (v *certVerifier) bindingProblem(cb certBinding) string {
	switch {
	case cb.form == formUnknown:
		return fmt.Sprintf("the timestamp declares an unknown anchor binding %s (this tool knows binding v1); use a newer lucairn-bundle-verify if Lucairn published one", quotedShort(cb.marker))
	case cb.required && cb.form != formV1:
		return fmt.Sprintf("this certificate was issued (signed issued_at %s) after %s, from which every certificate's anchors are content-bound (binding v1), but its timestamp does not declare binding v1: the marker was removed or the anchors are not this certificate's",
			cb.signedIssuedAt.Format(time.RFC3339), v.opt.Roots.BindingRequiredAfter.Format(time.RFC3339))
	}
	return ""
}

func (v *certVerifier) timestamp(scope string, cm, att map[string]any, issuedAt time.Time, anchorClaimed bool, cb certBinding) {
	r := v.r
	ts, _ := att["timestamp"].(map[string]any)
	token, okT := b64(ts["timestamp_token"])
	if !okT {
		r.add(scope, "timestamp", Fail, "timestamp_token is not base64")
		return
	}
	// The binding-marker requirement holds whether or not an anchor is
	// present (Sol #77 P1): a certificate issued after the cutover always
	// carries the marker (the witness records it with cert_hash when the
	// anchoring run starts, and keeps it when both rails fail), so removing
	// the anchors together with the marker must not turn TAMPERED into "not
	// anchored", which --allow-unanchored would then accept as VALID.
	if p := v.bindingProblem(cb); p != "" {
		r.add(scope, "timestamp", Fail, p)
		return
	}
	if len(token) == 0 {
		v.notAnchored(scope, "timestamp", "no timestamp token", anchorClaimed)
		return
	}
	digest, ok := b64(ts["cert_hash"])
	if !ok || len(digest) != sha256.Size {
		r.add(scope, "timestamp", Fail, "the certificate's recorded digest (cert_hash) is missing or not SHA-256")
		return
	}
	expected, status, over := digest, PassNotContentBound, "the recorded digest"
	if cb.form == formV1 {
		if cb.h == nil {
			r.skip(scope, "timestamp", "binding v1 cannot be checked: this certificate's witness signature was not verified", true)
			return
		}
		expected, status, over = cb.h, PassContentBound, "this certificate's anchor-binding v1 digest (recorded cert_hash + signed content)"
	} else {
		r.notContentBound = true
	}
	res, err := anchor.VerifyTimestamp(token, expected, v.opt.Roots.TSARoots, v.opt.Now)
	if err != nil {
		msg := short(err.Error())
		if cb.form == formV1 {
			msg = "anchor binding v1 (the expected imprint is the binding digest recomputed from this certificate): " + msg
		}
		r.add(scope, "timestamp", Fail, msg)
		return
	}
	if !issuedAt.IsZero() && res.GenTime.Before(issuedAt.Add(-anchor.ClockSkew)) {
		r.add(scope, "timestamp", Fail, "the timestamp predates the certificate it is attached to")
		return
	}
	if de, _ := cm["decoder_expiry"].(map[string]any); de != nil {
		if sup := str(de["superseded_anchor_sha256"]); sup != "" && !strings.EqualFold(sup, hex.EncodeToString(digest)) {
			r.add(scope, "timestamp", Fail, "decoder_expiry names a different anchored digest than the timestamp")
			return
		}
	}
	key := hex.EncodeToString(digest)
	if other, dup := v.seenTSA[key]; dup {
		r.add(scope, "timestamp", Fail, "the same timestamp digest is attached to certificate "+other)
		return
	}
	v.seenTSA[key] = scope
	detail := fmt.Sprintf("RFC 3161 token over %s, genTime %s, signer %s", over, res.GenTime.Format(time.RFC3339), res.SignerCN)
	if !res.ChainValidNow {
		detail += " (signing chain valid at genTime, expired since; revocation not checked offline)"
	}
	r.add(scope, "timestamp", status, detail)
	r.Steps[len(r.Steps)-1].SignerDN = res.Signer
}

func (v *certVerifier) rekor(scope string, att map[string]any, issuedAt time.Time, anchorClaimed bool, wkey ed25519.PublicKey, cb certBinding) {
	r := v.r
	tl, _ := att["transparency_log"].(map[string]any)
	set, ok1 := b64(tl["signed_entry_timestamp"])
	proof, ok2 := b64(tl["inclusion_proof"])
	body, ok3 := b64(tl["canonical_body"])
	idx, hasIdx, ok4 := int64Field(tl["log_index"])
	itime, _, ok5 := int64Field(tl["integrated_time"])
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		r.add(scope, "rekor", Fail, "transparency_log fields do not decode")
		return
	}
	if len(set) == 0 && len(proof) == 0 && len(body) == 0 && (!hasIdx || idx == 0) {
		// Same rule as the timestamp step: a binding problem fails this step
		// even without an entry (Sol #77 P1).
		if p := v.bindingProblem(cb); p != "" {
			r.add(scope, "rekor", Fail, p)
			return
		}
		v.notAnchored(scope, "rekor", "no Rekor entry", anchorClaimed)
		return
	}
	e := anchor.RekorEntry{LogIndex: idx, InclusionProof: proof, SignedEntryTimestamp: set, CanonicalBody: body, IntegratedTime: itime}
	if v.opt.Fetcher != nil {
		var err error
		e, err = v.online(e, wkey)
		if err != nil {
			r.add(scope, "rekor", Fail, short(err.Error()))
			return
		}
	}
	// The STORED entry (with a legacy body/time filled in from the log in
	// --online mode) is what is verified: the log's copy only confirms it.
	res, err := anchor.VerifyRekor(e, v.opt.Roots.Rekor, wkey)
	if errors.Is(err, anchor.ErrRekorNoBody) {
		r.skip(scope, "rekor", "legacy entry without a stored body; re-run with --online to check it against the log", true)
		return
	}
	if err != nil {
		r.add(scope, "rekor", Fail, short(err.Error()))
		return
	}
	if !issuedAt.IsZero() && res.IntegratedTime.Before(issuedAt.Add(-anchor.ClockSkew)) {
		r.add(scope, "rekor", Fail, "the Rekor entry predates the certificate it is attached to")
		return
	}
	// Any binding problem fails this step too, not only an unknown marker: a
	// certificate issued after the cutover whose timestamp half does not
	// declare binding v1 has had its (unsigned) marker edited, even when its
	// Rekor entry happens to be the bound one — e.g. a Rekor-only certificate
	// (TSA rail failed) with its marker stripped. Same rule as the timestamp
	// step and the witness's /verify.
	if p := v.bindingProblem(cb); p != "" {
		r.add(scope, "rekor", Fail, p)
		return
	}
	bound := cb.h != nil && strings.EqualFold(res.ArtifactSHA512, anchor.RekorDigestV1(cb.h))
	status := PassNotContentBound
	switch {
	case cb.form == formV1 || cb.required:
		if cb.h == nil {
			r.skip(scope, "rekor", "content binding cannot be checked: it needs a verified witness signature and the timestamp's recorded cert_hash", true)
			return
		}
		if !bound {
			r.add(scope, "rekor", Fail, "the Rekor entry is not for this certificate's anchor-binding v1 digest (an entry of another certificate, or one made without binding v1)")
			return
		}
		status = PassContentBound
	case bound:
		// A legacy-marked timestamp with a binding-v1 log entry: an anchoring
		// run resumed across the witness upgrade. The entry itself is bound.
		status = PassContentBound
	case cb.form == formLegacy && cb.certHash != nil && strings.EqualFold(res.ArtifactSHA512, anchor.RekorDigestV1(cb.certHash)):
		// A legacy entry logs sha512(certificate_raw), and the legacy
		// cert_hash is sha256(certificate_raw): they coincide only if the
		// stored bytes were their own SHA-256. An entry for sha512(cert_hash)
		// is a binding-v1 anchor (H = cert_hash) of ANOTHER certificate,
		// relabelled as legacy (T-1231 S2a, Sol #747 P1 shape).
		r.add(scope, "rekor", Fail, "the timestamp declares the legacy form, but the Rekor entry is for sha512(cert_hash): a binding-v1 anchor of another certificate relabelled as legacy")
		return
	default:
		r.notContentBound = true
	}
	idxKey := strconv.FormatInt(e.LogIndex, 10)
	if other, dup := v.seenRekor[idxKey]; dup {
		r.add(scope, "rekor", Fail, "the same Rekor entry is attached to certificate "+other)
		return
	}
	if other, dup := v.seenBody[res.ArtifactSHA512]; dup {
		r.add(scope, "rekor", Fail, "the same logged digest is attached to certificate "+other)
		return
	}
	v.seenRekor[idxKey], v.seenBody[res.ArtifactSHA512] = scope, scope
	cp := "no signed checkpoint in the proof"
	if res.Checkpoint {
		cp = "signed checkpoint verified"
	}
	mode := "stored entry"
	if v.opt.Fetcher != nil {
		mode = "stored entry, confirmed by the log's current copy"
	}
	what := ""
	if status == PassContentBound {
		what = "; the entry logs this certificate's anchor-binding v1 digest"
	}
	r.add(scope, "rekor", status, fmt.Sprintf("log index %d, integrated %s; SET + inclusion proof verified, %s; entry made by the witness key (%s)%s",
		e.LogIndex, res.IntegratedTime.Format(time.RFC3339), cp, mode, what))
}

// online re-fetches the entry from the log. The log's copy CONFIRMS the
// stored entry and never replaces it: the stored SET and the stored
// inclusion proof are still the ones verified (by the caller). Only a legacy
// entry that never stored its body / integrated time gets those two values
// from the log — and they must then match the STORED SET. The log's own copy
// must verify too (SET, proof, checkpoint, witness key).
func (v *certVerifier) online(stored anchor.RekorEntry, wkey ed25519.PublicKey) (anchor.RekorEntry, error) {
	return confirmOnline(v.opt.Fetcher, v.opt.Roots.Rekor, stored, wkey, "witness")
}

// notAnchored reports a missing anchor. It is never a PASS. It blocks VALID
// when the trust roots require anchors (the built-in Lucairn-hosted pins,
// or --require-anchors), and otherwise when the certificate's own (unsigned)
// anchor_status says ANCHORED — anchor_status can make a result worse, never
// better: removing it never relaxes the requirement.
func (v *certVerifier) notAnchored(scope, step, what string, anchorClaimed bool) {
	if v.opt.Roots.RequireAnchors {
		v.r.skip(scope, step, "not anchored: "+what+"; every certificate must be anchored under these trust roots (for a self-hosted deployment without anchoring pass --allow-unanchored)", true)
		return
	}
	if anchorClaimed {
		v.r.skip(scope, step, "not anchored: "+what+", although the certificate states it is anchored", true)
		return
	}
	v.r.skip(scope, step, "not anchored: "+what, false)
}

func anchorStatusClaimsAnchored(cm map[string]any) bool {
	as, _ := cm["anchor_status"].(map[string]any)
	return str(as["status"]) == "ANCHOR_STATUS_ANCHORED"
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// b64 decodes a protojson bytes field: absent/null/"" → (nil, true).
func b64(v any) ([]byte, bool) {
	if v == nil {
		return nil, true
	}
	s, ok := v.(string)
	if !ok {
		return nil, false
	}
	if s == "" {
		return nil, true
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	return b, true
}

// int64Field decodes a protojson int64 (a JSON string) or a JSON number:
// returns (value, present, ok).
func int64Field(v any) (int64, bool, bool) {
	switch x := v.(type) {
	case nil:
		return 0, false, true
	case string:
		if x == "" {
			return 0, false, true
		}
		n, err := strconv.ParseInt(x, 10, 64)
		return n, err == nil, err == nil
	case json.Number:
		n, err := x.Int64()
		return n, err == nil, err == nil
	}
	return 0, false, false
}
