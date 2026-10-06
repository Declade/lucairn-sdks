// Command lucairn-bundle-verify checks a Lucairn evidence bundle offline.
//
//	lucairn-bundle-verify [flags] bundle.zip
//
// It recomputes, from the files in the bundle and keys built into this
// binary (or given on the command line — never taken from the bundle):
//
//   - every file against the bundle manifest (SHA-256, nothing unlisted);
//   - every certificate's witness signature and every claim signature;
//   - that the signed claims name the bundle's conversation and customer;
//   - every RFC 3161 timestamp token against the pinned TSA root;
//   - every Sigstore Rekor entry (signed entry timestamp, inclusion proof,
//     checkpoint, and that the witness key made the entry);
//   - for certificates with anchor binding v1, that both anchors commit to a
//     digest recomputed from the certificate's signature-verified content
//     (PASS (content-bound)); older anchors print PASS (genuine anchor, not
//     content-bound). With the built-in pins, a certificate whose signed
//     issued_at is after the hosted binding cutover must be content-bound,
//     otherwise it is TAMPERED (--require-binding-after sets the same guard
//     for another deployment).
//
// A format-2 bundle also carries the audit/ folder, and the tool checks:
//
//   - the per-conversation request counter: every counter entry recomputes
//     its event_hash (conversation and number are inside the hash), the
//     numbers run 1..N without a gap or duplicate, every certificate's
//     audit-signed claim names its entry, and every counted request has its
//     certificate — a certificate removed together with its manifest line is
//     no longer invisible;
//   - every counted request's inclusion in the audit log's Merkle tree, at
//     the tree size and root of a root artifact that the pinned audit key
//     signed and logged in Rekor.
//
// The counter cannot show that request N is the last one (a cut-off tail),
// and before a root is logged the audit rows rest on the operator's key;
// both are printed as limitations on every run.
//
// With the built-in pins every certificate must be anchored (a missing
// timestamp or Rekor entry is INCOMPLETE); --allow-unanchored relaxes that
// for self-hosted deployments, and a custom --witness-key relaxes it unless
// --require-anchors is given. The manifest is unsigned in format 1, so the
// reports, verification.json and README.txt are checked against it but not
// authenticated (printed as a limitation on every run).
//
// Each step prints PASS, FAIL or SKIPPED(reason); INFO lines report what a
// certificate itself states (its own chain verdict, user_unredacted) and
// never change the result. Exit codes:
//
//	0  VALID       every check that applies passed
//	1  TAMPERED    at least one check failed
//	2  INCOMPLETE  nothing failed, but something that must be checked could
//	               not be (also: unreadable input, usage errors)
//
// The text report, the usage text and error messages are ASCII-only (a
// default Windows console garbles piped UTF-8); --json is UTF-8 JSON.
//
// PRD: specs/2026-10/prd-2026-10-06-evidence-bundle-export.md (Slices 1, 2a,
// 2b); design specs/2026-10/design-2026-10-06-t1231-s2b-audit-counter.md.
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/anchor"
	"github.com/declade/lucairn-sdks/go/internal/bundle"
)

// version is set at build time (-ldflags "-X main.version=…").
var version = "dev"

type kvList []string

func (k *kvList) String() string     { return strings.Join(*k, ",") }
func (k *kvList) Set(v string) error { *k = append(*k, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	// Usage, errors and the text report are ASCII-only (T-1242): a default
	// Windows console garbles piped UTF-8. The JSON report keeps stdout as is.
	rawStdout := stdout
	stdout, stderr = bundle.ASCIIWriter(stdout), bundle.ASCIIWriter(stderr)
	fs := flag.NewFlagSet("lucairn-bundle-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var witnessKeys, serviceKeys kvList
	jsonOut := fs.Bool("json", false, "print the report as JSON")
	online := fs.Bool("online", false, "also re-fetch every Rekor entry from the log (network); offline is the default")
	tsaRoot := fs.String("tsa-root", "", "PEM file with the TSA root certificate(s) to trust INSTEAD of the built-in FreeTSA root")
	rekorKey := fs.String("rekor-key", "", "PEM file with the Rekor public key to trust INSTEAD of the built-in public-good key")
	rekorURL := fs.String("rekor-url", bundle.PublicRekorURL, "Rekor API base for --online")
	printRoots := fs.Bool("print-trust-roots", false, "print the built-in trust roots and exit")
	requireAnchors := fs.Bool("require-anchors", false, "a certificate without a timestamp or Rekor entry makes the result INCOMPLETE (the default with the built-in pins; use it with --witness-key for an anchored self-hosted deployment)")
	allowUnanchored := fs.Bool("allow-unanchored", false, "a certificate without a timestamp or Rekor entry is reported SKIPPED(not anchored) without blocking VALID (self-hosted deployments without anchoring)")
	requireBindingAfter := fs.String("require-binding-after", "", "RFC 3339 time: a certificate whose signed issued_at is later must have content-bound (binding v1) anchors, otherwise TAMPERED (built in for the Lucairn-hosted pins; use it with --witness-key for a self-hosted deployment that knows its own cutover)")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Var(&witnessKeys, "witness-key", "KEY_ID=BASE64 witness Ed25519 key to trust INSTEAD of the built-in one (repeatable; self-hosted deployments)")
	fs.Var(&serviceKeys, "service-key", "SERVICE_ID=BASE64 claim-signing key to trust INSTEAD of the built-in set (repeatable)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: lucairn-bundle-verify [flags] bundle.zip")
		fmt.Fprintln(stderr, "exit codes: 0 VALID, 1 TAMPERED, 2 INCOMPLETE")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return bundle.ExitIncomplete
	}
	if *showVersion {
		fmt.Fprintln(stdout, "lucairn-bundle-verify", version)
		return 0
	}
	roots, err := bundle.ProductionRoots()
	if err != nil {
		fmt.Fprintln(stderr, "lucairn-bundle-verify:", err)
		return bundle.ExitIncomplete
	}
	if *printRoots {
		printTrustRoots(stdout, roots)
		return 0
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return bundle.ExitIncomplete
	}
	custom, err := applyOverrides(&roots, witnessKeys, serviceKeys, *tsaRoot, *rekorKey)
	if err != nil {
		fmt.Fprintln(stderr, "lucairn-bundle-verify:", err)
		return bundle.ExitIncomplete
	}
	if *requireAnchors && *allowUnanchored {
		fmt.Fprintln(stderr, "lucairn-bundle-verify: --require-anchors and --allow-unanchored exclude each other")
		return bundle.ExitIncomplete
	}
	if len(witnessKeys) > 0 {
		// Another deployment: it may run without anchoring (air-gapped kit),
		// and it upgrades its witness to anchor binding v1 on its own schedule.
		roots.RequireAnchors = false
		if !*requireAnchors && !*allowUnanchored {
			custom = append(custom, "unanchored certificates allowed")
		}
		roots.BindingRequiredAfter = time.Time{}
		if *requireBindingAfter == "" {
			// Say so on the banner: a custom witness key silently dropping
			// the downgrade guard is exactly what a reader must see (ToB #77 L1).
			custom = append(custom, "anchor-binding cutover not enforced")
		}
	}
	if *requireBindingAfter != "" {
		t, err := time.Parse(time.RFC3339, *requireBindingAfter)
		if err != nil {
			fmt.Fprintln(stderr, "lucairn-bundle-verify: --require-binding-after must be an RFC 3339 time, e.g. 2026-11-01T00:00:00Z")
			return bundle.ExitIncomplete
		}
		roots.BindingRequiredAfter = t.UTC()
		custom = append(custom, "binding required after "+t.UTC().Format(time.RFC3339))
	}
	if *requireAnchors {
		roots.RequireAnchors = true
	}
	if *allowUnanchored {
		roots.RequireAnchors = false
		custom = append(custom, "unanchored certificates allowed")
	}
	if len(custom) > 0 {
		roots.Label = "CUSTOM (given on the command line, not the Lucairn-hosted pins): " + strings.Join(custom, ", ")
	}
	path := fs.Arg(0)
	data, err := readBounded(path)
	if err != nil {
		fmt.Fprintln(stderr, "lucairn-bundle-verify:", err)
		return bundle.ExitIncomplete
	}
	opt := bundle.Options{Roots: roots}
	if *online {
		opt.Fetcher = bundle.NewHTTPRekorFetcher(strings.TrimRight(*rekorURL, "/"))
	}
	rep := bundle.Verify(filepath.Base(path), data, opt)
	if *jsonOut {
		if err := rep.WriteJSON(rawStdout); err != nil {
			return bundle.ExitIncomplete
		}
	} else {
		rep.WriteText(stdout)
	}
	return rep.ExitCode
}

func readBounded(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, bundle.MaxBundleBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > bundle.MaxBundleBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, bundle.MaxBundleBytes)
	}
	return b, nil
}

func parseKey(kv string) (string, ed25519.PublicKey, error) {
	id, val, ok := strings.Cut(kv, "=")
	if !ok || id == "" {
		return "", nil, fmt.Errorf("key %q must be ID=BASE64", kv)
	}
	b, err := base64.StdEncoding.DecodeString(val)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("key for %q must be the standard base64 of 32 bytes", id)
	}
	return id, ed25519.PublicKey(b), nil
}

func applyOverrides(roots *bundle.TrustRoots, witness, service kvList, tsaRoot, rekorKey string) ([]string, error) {
	var custom []string
	if len(witness) > 0 {
		roots.WitnessKeys = map[string]ed25519.PublicKey{}
		for _, kv := range witness {
			id, k, err := parseKey(kv)
			if err != nil {
				return nil, err
			}
			roots.WitnessKeys[id] = k
		}
		custom = append(custom, "witness key")
	}
	if len(service) > 0 {
		roots.ServiceKeys = map[string]ed25519.PublicKey{}
		for _, kv := range service {
			id, k, err := parseKey(kv)
			if err != nil {
				return nil, err
			}
			roots.ServiceKeys[id] = k
		}
		custom = append(custom, "service keys")
	} else if len(witness) > 0 {
		// A different witness implies a different deployment: the built-in
		// service keys are not its keys. Claims are then SKIPPED (INCOMPLETE).
		roots.ServiceKeys = nil
	}
	if tsaRoot != "" {
		b, err := os.ReadFile(tsaRoot)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return nil, errors.New("--tsa-root holds no PEM certificate")
		}
		roots.TSARoots = pool
		custom = append(custom, "TSA root")
	}
	if rekorKey != "" {
		b, err := os.ReadFile(rekorKey)
		if err != nil {
			return nil, err
		}
		rk, err := anchor.ParseRekorKeyPEM(b)
		if err != nil {
			return nil, err
		}
		roots.Rekor = rk
		custom = append(custom, "Rekor key")
	}
	return custom, nil
}

func printTrustRoots(w io.Writer, roots bundle.TrustRoots) {
	fmt.Fprintln(w, "Built-in trust roots (Lucairn-hosted deployment):")
	ids := make([]string, 0, len(roots.WitnessKeys))
	for id := range roots.WitnessKeys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		fmt.Fprintf(w, "  witness  %-24s %s\n", id, base64.StdEncoding.EncodeToString(roots.WitnessKeys[id]))
	}
	svc := make([]string, 0, len(roots.ServiceKeys))
	for id := range roots.ServiceKeys {
		svc = append(svc, id)
	}
	sort.Strings(svc)
	for _, id := range svc {
		fmt.Fprintf(w, "  service  %-24s %s\n", id, base64.StdEncoding.EncodeToString(roots.ServiceKeys[id]))
	}
	fmt.Fprintf(w, "  tsa      FreeTSA root CA          sha256(pem) %s\n", anchor.FreeTSARootSHA256)
	fmt.Fprintf(w, "  rekor    public-good log          log id %s\n", roots.Rekor.LogID)
	fmt.Fprintf(w, "  binding  content-bound anchors required for certificates issued after %s\n", roots.BindingRequiredAfter.Format(time.RFC3339))
	fmt.Fprintf(w, "  audit    audit roots and the per-conversation counter are checked under the service key %s\n", anchor.AuditRootSigner)
	fmt.Fprintln(w, "Compare with https://lucairn.eu/.well-known/lucairn-service-keys.json out of band.")
}
