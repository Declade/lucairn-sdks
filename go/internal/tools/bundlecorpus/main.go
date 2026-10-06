// Command bundlecorpus writes the SYNTHETIC lucairn-bundle-verify tamper corpus to a
// directory, for cmd/lucairn-bundle-verify/scripts/tamper-corpus.sh to run against
// the built binary:
//
//	<out>/cases/<name>.zip      one bundle per case
//	<out>/expected.tsv          name, expectation, description, extra flags
//	                            (space-separated; @REKOR_URL@ = the -serve URL)
//	<out>/flags.txt             lucairn-bundle-verify flags that trust the synthetic world
//	<out>/rekor-entries.json    the synthetic log's entries, for -serve
//	<out>/trust/*.pem           synthetic TSA root + leaf, synthetic Rekor key
//	<out>/clean-certs/          the clean bundle's certificates + meta.json, so
//	                            another bundle WRITER (the website's) can be
//	                            checked against the same tool
//
// bundlecorpus -serve DIR -port-file F serves DIR/rekor-entries.json as a
// Rekor v1 API on 127.0.0.1 (a free port, written to F) for the --online
// cases. bundlecorpus -legacy-manifest writes round-1 manifests
// (completeness.state) for the RED-PROOF run against the pre-fix binary.
//
// Synthetic only: its own keys, certificates and anchors. No production data.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

func main() {
	out := flag.String("out", "", "output directory (created)")
	legacy := flag.Bool("legacy-manifest", false, "write round-1 manifests (completeness.state) for the RED-PROOF run against the pre-fix binary")
	serve := flag.String("serve", "", "serve DIR/rekor-entries.json as a Rekor v1 API on 127.0.0.1 until killed")
	portFile := flag.String("port-file", "", "with -serve: write the base URL to this file once listening")
	flag.Parse()
	if *serve != "" {
		if err := serveEntries(*serve, *portFile); err != nil {
			fmt.Fprintln(os.Stderr, "bundlecorpus:", err)
			os.Exit(1)
		}
		return
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: bundlecorpus -out DIR [-legacy-manifest] | -serve DIR -port-file F")
		os.Exit(2)
	}
	bundletest.LegacyManifest = *legacy
	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "bundlecorpus:", err)
		os.Exit(1)
	}
}

func run(out string) error {
	co, err := bundletest.NewCorpus()
	if err != nil {
		return err
	}
	for _, d := range []string{"cases", "trust", "clean-certs"} {
		if err := os.MkdirAll(filepath.Join(out, d), 0o755); err != nil {
			return err
		}
	}
	tsaRoot := filepath.Join(out, "trust", "tsa-root.pem")
	rekor := filepath.Join(out, "trust", "rekor.pem")
	writes := map[string][]byte{
		tsaRoot: co.World.TSARootPEM(),
		filepath.Join(out, "trust", "tsa-leaf.pem"): co.World.TSALeafPEM(),
		rekor:                           co.World.RekorPEM(),
		filepath.Join(out, "flags.txt"): []byte(strings.Join(co.World.CLIFlags(tsaRoot, rekor), "\n") + "\n"),
	}
	var tsv strings.Builder
	for _, c := range co.Cases {
		writes[filepath.Join(out, "cases", c.Name+".zip")] = c.Zip
		fmt.Fprintf(&tsv, "%s\t%s\t%s\t%s\n", c.Name, c.Expect, c.What, strings.Join(c.Flags, " "))
	}
	writes[filepath.Join(out, "expected.tsv")] = []byte(tsv.String())
	eb, err := json.Marshal(co.Entries)
	if err != nil {
		return err
	}
	writes[filepath.Join(out, "rekor-entries.json")] = eb
	meta := co.Clean.Manifest()
	for _, c := range meta.Certificates {
		writes[filepath.Join(out, "clean-certs", filepath.Base(c.Path))] = co.Clean[c.Path]
	}
	mb, _ := json.MarshalIndent(map[string]any{
		"conversation_id": meta.ConversationID, "customer_id": meta.CustomerID, "certificates": meta.Certificates,
	}, "", "  ")
	writes[filepath.Join(out, "clean-certs", "meta.json")] = mb
	for p, b := range writes {
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func serveEntries(dir, portFile string) error {
	b, err := os.ReadFile(filepath.Join(dir, "rekor-entries.json"))
	if err != nil {
		return err
	}
	co := &bundletest.Corpus{}
	if err := json.Unmarshal(b, &co.Entries); err != nil {
		return err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	if portFile != "" {
		if err := os.WriteFile(portFile, []byte("http://"+ln.Addr().String()+"\n"), 0o644); err != nil {
			return err
		}
	}
	return http.Serve(ln, co.RekorHandler())
}
