// Command lucairn-verify checks a Lucairn evidence bundle offline.
//
//	lucairn-verify [flags] bundle.zip
//
// It recomputes, from the files in the bundle and keys built into this
// binary (or given on the command line — never taken from the bundle):
//
//   - every file against the bundle manifest (SHA-256, nothing unlisted);
//   - every certificate's witness signature and every claim signature;
//   - that the signed claims name the bundle's conversation and customer;
//   - every RFC 3161 timestamp token against the pinned TSA root;
//   - every Sigstore Rekor entry (signed entry timestamp, inclusion proof,
//     checkpoint, and that the witness key made the entry).
//
// Each step prints PASS, FAIL or SKIPPED(reason). Exit codes:
//
//	0  VALID       every check that applies passed
//	1  TAMPERED    at least one check failed
//	2  INCOMPLETE  nothing failed, but something that must be checked could
//	               not be (also: unreadable input, usage errors)
//
// PRD: specs/2026-10/prd-2026-10-06-evidence-bundle-export.md (Slice 1).
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
	fs := flag.NewFlagSet("lucairn-verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var witnessKeys, serviceKeys kvList
	jsonOut := fs.Bool("json", false, "print the report as JSON")
	online := fs.Bool("online", false, "also re-fetch every Rekor entry from the log (network); offline is the default")
	tsaRoot := fs.String("tsa-root", "", "PEM file with the TSA root certificate(s) to trust INSTEAD of the built-in FreeTSA root")
	rekorKey := fs.String("rekor-key", "", "PEM file with the Rekor public key to trust INSTEAD of the built-in public-good key")
	rekorURL := fs.String("rekor-url", bundle.PublicRekorURL, "Rekor API base for --online")
	printRoots := fs.Bool("print-trust-roots", false, "print the built-in trust roots and exit")
	showVersion := fs.Bool("version", false, "print the version and exit")
	fs.Var(&witnessKeys, "witness-key", "KEY_ID=BASE64 witness Ed25519 key to trust INSTEAD of the built-in one (repeatable; self-hosted deployments)")
	fs.Var(&serviceKeys, "service-key", "SERVICE_ID=BASE64 claim-signing key to trust INSTEAD of the built-in set (repeatable)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: lucairn-verify [flags] bundle.zip")
		fmt.Fprintln(stderr, "exit codes: 0 VALID · 1 TAMPERED · 2 INCOMPLETE")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return bundle.ExitIncomplete
	}
	if *showVersion {
		fmt.Fprintln(stdout, "lucairn-verify", version)
		return 0
	}
	roots, err := bundle.ProductionRoots()
	if err != nil {
		fmt.Fprintln(stderr, "lucairn-verify:", err)
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
		fmt.Fprintln(stderr, "lucairn-verify:", err)
		return bundle.ExitIncomplete
	}
	if len(custom) > 0 {
		roots.Label = "CUSTOM (given on the command line, not the Lucairn-hosted pins): " + strings.Join(custom, ", ")
	}
	path := fs.Arg(0)
	data, err := readBounded(path)
	if err != nil {
		fmt.Fprintln(stderr, "lucairn-verify:", err)
		return bundle.ExitIncomplete
	}
	opt := bundle.Options{Roots: roots}
	if *online {
		opt.Fetcher = bundle.NewHTTPRekorFetcher(strings.TrimRight(*rekorURL, "/"))
	}
	rep := bundle.Verify(filepath.Base(path), data, opt)
	if *jsonOut {
		if err := rep.WriteJSON(stdout); err != nil {
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
	fmt.Fprintln(w, "Compare with https://lucairn.eu/.well-known/lucairn-service-keys.json out of band.")
}
