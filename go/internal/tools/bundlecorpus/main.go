// Command bundlecorpus writes the SYNTHETIC lucairn-verify tamper corpus to a
// directory, for cmd/lucairn-verify/scripts/tamper-corpus.sh to run against
// the built binary:
//
//	<out>/cases/<name>.zip      one bundle per case
//	<out>/expected.tsv          name, expectation, description
//	<out>/flags.txt             lucairn-verify flags that trust the synthetic world
//	<out>/trust/*.pem           synthetic TSA root + leaf, synthetic Rekor key
//	<out>/clean-certs/          the clean bundle's certificates + meta.json, so
//	                            another bundle WRITER (the website's) can be
//	                            checked against the same tool
//
// Synthetic only: its own keys, certificates and anchors. No production data.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

func main() {
	out := flag.String("out", "", "output directory (created)")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "usage: bundlecorpus -out DIR")
		os.Exit(2)
	}
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
		fmt.Fprintf(&tsv, "%s\t%s\t%s\n", c.Name, c.Expect, c.What)
	}
	writes[filepath.Join(out, "expected.tsv")] = []byte(tsv.String())
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
