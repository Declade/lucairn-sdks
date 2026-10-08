package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
			if c.Name == "Cleaning-33-routed-partial-after-no-entry" || c.Name == "Cleaning-34-routed-partial-before-empty-audit" || c.Name == "Cleaning-35-marker-plus-dsa-ai-no-entry" {
				if !strings.Contains(human.String(), "every claim signature verifies") || !strings.Contains(human.String(), "PARTIAL (inference_unfinished") {
					t.Fatalf("%s/%s: routed claim chain did not verify: %s", c.Name, policy, &human)
				}
				if report["not_counted_cleaning_steps"] != nil || strings.Contains(human.String(), "not counted, no number expected") || strings.Contains(machine.String(), "not counted, no number expected") {
					t.Fatalf("%s/%s: unexpected before-start exemption: %s", c.Name, policy, &human)
				}
			}
			if n, _ := report["cleaning_steps"].(float64); n > 0 {
				scope, ok := report["cleaning_scope"].(string)
				if !ok || scope == "" || strings.Count(human.String(), scope) != 1 {
					t.Fatalf("%s/%s: scope missing or repeated", c.Name, policy)
				}
			}
		}
	}
}

func TestCleaningStartFlag(t *testing.T) {
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tsa, rekor := filepath.Join(dir, "tsa.pem"), filepath.Join(dir, "rekor.pem")
	for p, b := range map[string][]byte{tsa: co.World.TSARootPEM(), rekor: co.World.RekorPEM()} {
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var data []byte
	for _, c := range co.Cases {
		if c.Name == "Cleaning-27-at-start-no-entry" {
			data = c.Zip
		}
	}
	if data == nil {
		t.Fatal("missing fixture")
	}
	path := filepath.Join(dir, "start.zip")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	flags := co.World.CLIFlags(tsa, rekor)
	var base []string
	for i := 0; i < len(flags); i++ {
		if flags[i] == "--require-cleaning-from" {
			i++
			continue
		}
		base = append(base, flags[i])
	}
	for _, tc := range []struct {
		name, from string
		exit       int
		banner     string
	}{
		{"custom no start", "", 0, "cleaning-counter start not enforced"},
		{"exact start", bundletest.CorpusCleaningStart.Format(time.RFC3339), 2, "cleaning entries required from"},
		{"before start", bundletest.CorpusCleaningStart.Add(time.Second).Format(time.RFC3339), 0, "not counted, no number expected"},
		{"invalid start", "tomorrow", 2, "must be an RFC 3339 time"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{}, base...)
			if tc.from != "" {
				args = append(args, "--require-cleaning-from", tc.from)
			}
			args = append(args, path)
			var out, errb bytes.Buffer
			code := run(args, &out, &errb)
			if code != tc.exit || !strings.Contains(out.String()+errb.String(), tc.banner) {
				t.Fatalf("exit %d: %s %s", code, &out, &errb)
			}
		})
	}
	var out, errb bytes.Buffer
	if run([]string{"--print-trust-roots"}, &out, &errb) != 0 || !strings.Contains(out.String(), "cleaning counter entries required for cleaning certificates issued at or after 2026-10-08T09:07:53Z") {
		t.Fatalf("missing hosted start: %s %s", &out, &errb)
	}
}

func TestExplicitCutoffsRejectZeroTime(t *testing.T) {
	w, err := bundletest.NewWorld("zero-cutoffs")
	if err != nil {
		t.Fatal(err)
	}
	for _, flag := range []string{"--require-cleaning-from", "--require-binding-after"} {
		for _, value := range []string{"0001-01-01T00:00:00Z", "0001-01-01T01:00:00+01:00"} {
			for _, custom := range []bool{false, true} {
				mode := "hosted"
				var args []string
				if custom {
					mode = "custom"
					// Only the witness override is needed; rejection precedes reading the bundle.
					args = w.CLIFlags("unused-tsa", "unused-rekor")[:2]
				}
				t.Run(flag+"/"+value+"/"+mode, func(t *testing.T) {
					args = append(args, flag, value, "unused.zip")
					var out, errb bytes.Buffer
					code := run(args, &out, &errb)
					if code != 2 || out.Len() != 0 || !strings.Contains(errb.String(), flag+" must not be the zero time") {
						t.Fatalf("exit %d, stdout %q, stderr %q", code, out.String(), errb.String())
					}
				})
			}
		}
	}
}
