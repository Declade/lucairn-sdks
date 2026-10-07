package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

func TestCleaningCLIReportsAndAnchorFlags(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tsa, rekor := filepath.Join(dir, "tsa.pem"), filepath.Join(dir, "rekor.pem")
	for p, b := range map[string][]byte{tsa: co.World.TSARootPEM(), rekor: co.World.RekorPEM()} {
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range co.Cases {
		if !strings.HasPrefix(c.Name, "Cleaning-") || strings.Contains(strings.Join(c.Flags, " "), "--online") {
			continue
		}
		p := filepath.Join(dir, c.Name+".zip")
		if err := os.WriteFile(p, c.Zip, 0o644); err != nil {
			t.Fatal(err)
		}
		for _, policy := range []string{"required", "custom-default", "allow-unanchored"} {
			flags := co.World.CLIFlags(tsa, rekor)
			if policy != "required" {
				flags = flags[:len(flags)-1] // --require-anchors is last
			}
			if policy == "allow-unanchored" && len(c.Flags) == 0 {
				flags = append(flags, "--allow-unanchored")
			}
			var human, machine, stderr bytes.Buffer
			args := bundletest.CaseArgs(flags, c.Flags, "", p)
			code := run(args, &human, &stderr)
			jsonCode := run(append([]string{"--json"}, args...), &machine, &stderr)
			wantCode := map[string]int{bundletest.ExpectValid: 0, bundletest.ExpectTampered: 1, bundletest.ExpectIncomplete: 2}[c.Expect]
			if code != wantCode || jsonCode != wantCode {
				t.Fatalf("%s/%s: exit %d/%d, want %d\n%s\n%s", c.Name, policy, code, jsonCode, wantCode, human.String(), stderr.String())
			}
			var report map[string]any
			if err := json.Unmarshal(machine.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if code == 0 {
				scope, ok := report["cleaning_scope"].(string)
				if !ok || scope == "" || strings.Count(human.String(), scope) != 1 {
					t.Fatalf("%s/%s: scope missing or repeated", c.Name, policy)
				}
			}
		}
	}
}
