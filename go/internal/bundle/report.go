package bundle

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Status of one check.
type Status string

const (
	Pass    Status = "PASS"
	Fail    Status = "FAIL"
	Skipped Status = "SKIPPED"
	// PassNotContentBound is the ONLY passing state of the timestamp and
	// rekor steps: the anchor is genuine (trusted TSA / public log, made for
	// the digest the certificate records), but it cannot be tied to this
	// exported certificate's content. It never blocks VALID, and it is never
	// printed as a bare PASS.
	PassNotContentBound Status = "PASS_NOT_CONTENT_BOUND"
	// Info reports what a certificate itself states (its own chain verdict,
	// user_unredacted). It is not a check and never changes the verdict.
	Info Status = "INFO"
)

// ReportNotAuthenticatedReason (gap G3) is printed on every run that got
// past the manifest: the manifest is unsigned in format 1.
const ReportNotAuthenticatedReason = "Report content not authenticated: report-external.pdf, report-internal.pdf, verification.json and README.txt match the manifest digests, but the manifest itself is unsigned, so no signature covers these files. Only the certificates are signed."

// ValidMeaning is printed under a VALID result.
const ValidMeaning = "VALID means the certificates are intact, signed by the pinned keys and belong to this conversation and account. It is a statement about the bundle's integrity, not that every turn was sanitized: read each certificate's chain-verdict and user-unredacted lines."

// AnchorsNotRequiredReason is printed whenever the trust roots do not require
// anchoring (custom --witness-key without --require-anchors, or
// --allow-unanchored).
const AnchorsNotRequiredReason = "anchors were not required: a certificate without a timestamp or Rekor entry would not have blocked VALID (it is reported as SKIPPED(not anchored))"

// NotContentBoundLabel is how PassNotContentBound is printed.
const NotContentBoundLabel = "PASS (genuine anchor, not content-bound)"

// NotContentBoundReason is printed under every PassNotContentBound step and
// in the result summary whenever an anchor step ran. The website's verify
// page and README.txt carry the same sentence.
const NotContentBoundReason = "The timestamp and log entry cover the certificate as stored by Lucairn, which contains original data and is not exported, so this tool cannot tie them to this exact certificate."

// Verdicts and their exit codes.
const (
	VerdictValid      = "VALID"
	VerdictTampered   = "TAMPERED"
	VerdictIncomplete = "INCOMPLETE"

	ExitValid      = 0
	ExitTampered   = 1
	ExitIncomplete = 2
)

// Step is one reported check. Scope is "bundle" or a certificate's request id.
type Step struct {
	Scope  string `json:"scope"`
	Name   string `json:"step"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
	// SignerDN is the full distinguished name of the TSA signer (timestamp
	// step only); the text report prints just its common name.
	SignerDN string `json:"signer_dn,omitempty"`
	// Incomplete marks a SKIPPED step whose absence means the bundle cannot
	// be called VALID (as opposed to a skip that is expected for this bundle
	// version, such as the audit counter in v1).
	Incomplete bool `json:"blocks_valid,omitempty"`
}

// Report is the result of verifying one bundle.
type Report struct {
	Bundle             string `json:"bundle"`
	ConversationID     string `json:"conversation_id,omitempty"`
	Certificates       int    `json:"certificates"`
	CertificatesDigest string `json:"certificates_digest,omitempty"`
	TrustRoots         string `json:"trust_roots"`
	Online             bool   `json:"online"`
	Steps              []Step `json:"steps"`
	// Limitations lists result-level caveats that apply to THIS run
	// (NotContentBoundReason whenever an anchor step ran).
	Limitations []string `json:"limitations"`
	Verdict     string   `json:"verdict"`
	ExitCode    int      `json:"exit_code"`
	NotCovered  []string `json:"not_covered"`

	reportUnauthenticated bool
	anchorsNotRequired    bool
}

func (r *Report) add(scope, name string, st Status, detail string) {
	r.Steps = append(r.Steps, Step{Scope: scope, Name: name, Status: st, Detail: detail})
}

func (r *Report) info(scope, name, detail string) {
	r.Steps = append(r.Steps, Step{Scope: scope, Name: name, Status: Info, Detail: detail})
}

func (r *Report) skip(scope, name, reason string, blocks bool) {
	r.Steps = append(r.Steps, Step{Scope: scope, Name: name, Status: Skipped, Detail: reason, Incomplete: blocks})
}

// finish computes the verdict: any FAIL → TAMPERED (1); otherwise any
// blocking SKIPPED → INCOMPLETE (2); otherwise VALID (0).
func (r *Report) finish() {
	fail, incomplete, anchorRan := false, false, false
	for _, s := range r.Steps {
		if (s.Name == "timestamp" || s.Name == "rekor") && (s.Status == PassNotContentBound || s.Status == Fail) {
			anchorRan = true
		}
		switch {
		case s.Status == Fail:
			fail = true
		case s.Status == Skipped && s.Incomplete:
			incomplete = true
		}
	}
	r.Limitations = nil
	if anchorRan {
		r.Limitations = append(r.Limitations, NotContentBoundReason)
	}
	if r.reportUnauthenticated {
		r.Limitations = append(r.Limitations, ReportNotAuthenticatedReason)
	}
	if r.anchorsNotRequired {
		r.Limitations = append(r.Limitations, AnchorsNotRequiredReason)
	}
	switch {
	case fail:
		r.Verdict, r.ExitCode = VerdictTampered, ExitTampered
	case incomplete:
		r.Verdict, r.ExitCode = VerdictIncomplete, ExitIncomplete
	default:
		r.Verdict, r.ExitCode = VerdictValid, ExitValid
	}
}

// NotCoveredV1 is printed on every run: what a v1 bundle cannot show.
var NotCoveredV1 = []string{
	"Completeness: v1 bundles carry no per-conversation request counter, so a certificate removed TOGETHER WITH its manifest entry is not detectable (planned: audit counter, bundle format 2).",
	"Anchor content binding: the timestamp and the Rekor entry commit to a digest of the witness's stored certificate bytes, which are not in the bundle. The tool checks that a trusted timestamp authority and the public Rekor log committed to the digest the certificate RECORDS, and that the witness key made the Rekor entry; it cannot recompute that digest from the certificate JSON.",
	"PDF content: the reports are integrity-checked against the manifest only. Their text is not compared with the certificates; the verify page prints the certificate-set digest so a reader can match them by hand.",
	"Report authenticity: the manifest is unsigned in this bundle version, so the reports, verification.json and README.txt are consistent with it but not authenticated by any signature. Someone who replaces a report and updates its manifest digest is not detected; only the certificates are signed.",
	"Sanitization: a VALID result is about the bundle's integrity. Whether a turn was sanitized is what each certificate's own chain verdict says, printed per certificate.",
	"verification.json is Lucairn's export-time record. It is never used as evidence; every check above is recomputed.",
}

// WriteText renders the report for a terminal.
func (r *Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "lucairn-bundle-verify — %s\n", r.Bundle)
	if r.ConversationID != "" {
		fmt.Fprintf(w, "conversation      %s\n", r.ConversationID)
	}
	fmt.Fprintf(w, "certificates      %d\n", r.Certificates)
	if r.CertificatesDigest != "" {
		fmt.Fprintf(w, "certificate set   %s\n", r.CertificatesDigest)
	}
	fmt.Fprintf(w, "trust roots       %s\n", r.TrustRoots)
	if r.Online {
		fmt.Fprintln(w, "mode              online (Rekor entries re-fetched)")
	} else {
		fmt.Fprintln(w, "mode              offline")
	}
	fmt.Fprintln(w)
	scope := ""
	for _, s := range r.Steps {
		if s.Scope != scope {
			scope = s.Scope
			if scope == "bundle" {
				fmt.Fprintln(w, "[bundle]")
			} else {
				fmt.Fprintf(w, "[certificate %s]\n", scope)
			}
		}
		status := string(s.Status)
		if s.Status == Info {
			fmt.Fprintf(w, "  %-16s INFO — %s\n", s.Name, s.Detail)
			continue
		}
		if s.Status == PassNotContentBound {
			fmt.Fprintf(w, "  %-16s %s — %s\n", s.Name, NotContentBoundLabel, s.Detail)
			fmt.Fprintf(w, "  %-16s   %s\n", "", NotContentBoundReason)
			continue
		}
		if s.Status == Skipped {
			status = "SKIPPED(" + s.Detail + ")"
			if s.Incomplete {
				status += " → blocks VALID"
			}
			fmt.Fprintf(w, "  %-16s %s\n", s.Name, status)
			continue
		}
		if s.Detail != "" {
			fmt.Fprintf(w, "  %-16s %s — %s\n", s.Name, status, s.Detail)
		} else {
			fmt.Fprintf(w, "  %-16s %s\n", s.Name, status)
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "NOT COVERED by this bundle version:")
	for _, n := range r.NotCovered {
		fmt.Fprintf(w, "  - %s\n", n)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "RESULT: %s (exit %d)\n", r.Verdict, r.ExitCode)
	for _, l := range r.Limitations {
		fmt.Fprintf(w, "LIMITATION: %s\n", l)
	}
	switch r.Verdict {
	case VerdictValid:
		fmt.Fprintln(w, ValidMeaning)
	case VerdictTampered:
		fmt.Fprintln(w, "At least one check FAILED: the bundle does not match what Lucairn issued.")
	case VerdictIncomplete:
		fmt.Fprintln(w, "No check failed, but at least one could not be performed. Read the SKIPPED lines.")
	}
	fmt.Fprintln(w, "This is a technical integrity check, not a certification or legal opinion.")
}

// WriteJSON renders the report as one JSON document.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func short(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 300 {
		return s[:300] + "…"
	}
	return s
}
