package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/bundle"
	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

// TestCleaningOfflineCompatibility builds the released verifier from the
// immutable 1.1.0 sources, through a Go overlay.
// This overlay cannot remove a non-test file added after 1.1.0; newly added
// production files in packages used by the old command need a fresh check.
// No checkout, git write, network, loopback server or background process.
func TestCleaningOfflineCompatibility(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 240*time.Second)
	defer cancel()
	dir := t.TempDir()
	gomod, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	git := func(args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = gomod
		out, err := cmd.CombinedOutput()
		if err != nil {
			message := fmt.Sprintf("1.1.0 compatibility sources unavailable (git missing, tag absent, shallow clone or tarball): git %v: %v\n%s", args, err, out)
			if os.Getenv("LUCAIRN_REQUIRE_COMPAT") == "1" {
				t.Fatal(message)
			}
			t.Skip(message)
		}
		return out
	}
	repo := strings.TrimSpace(string(git("rev-parse", "--show-toplevel")))
	const baseline = "dcfd2a513964b6366ad3390f429c6c2b313d6df6"
	if got := strings.TrimSpace(string(git("rev-parse", "bundle-verify-v1.1.0^{commit}"))); got != baseline {
		t.Fatalf("1.1.0 tag moved: %s", got)
	}
	replace := map[string]string{}
	for _, p := range strings.Split(string(git("ls-tree", "-rz", "--full-name", "--name-only", baseline, "--", ".")), "\x00") {
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			continue
		}
		dst := filepath.Join(dir, "old", p)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, git("show", baseline+":"+p), 0o600); err != nil {
			t.Fatal(err)
		}
		replace[filepath.Join(repo, p)] = dst
	}
	overlay, err := json.Marshal(map[string]any{"Replace": replace})
	if err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0o600); err != nil {
		t.Fatal(err)
	}
	old := filepath.Join(dir, "verify-1.1.0")
	cmd := exec.CommandContext(ctx, "go", "build", "-overlay", overlayPath, "-o", old, "./cmd/lucairn-bundle-verify")
	cmd.Dir = gomod
	// Keep the overlay build cache separate from current-package builds.
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOFLAGS=", "GOCACHE="+filepath.Join(dir, "old-cache"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("offline old build: %v\n%s", err, out)
	}
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	tsa, rekor := filepath.Join(dir, "tsa.pem"), filepath.Join(dir, "rekor.pem")
	for p, b := range map[string][]byte{tsa: co.World.TSARootPEM(), rekor: co.World.RekorPEM()} {
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// Explicit genuine-alteration exceptions only. None are needed: even
	// Cleaning-02-type-rehashed fails inclusion under both versions.
	genuineAlterations := map[string]string{}
	for _, c := range co.Cases {
		if strings.Contains(strings.Join(c.Flags, " "), "--online") {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			p := filepath.Join(dir, c.Name+".zip")
			if err := os.WriteFile(p, c.Zip, 0o600); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"--json"}, bundletest.CaseArgs(co.World.CLIFlags(tsa, rekor), c.Flags, "", p)...)
			var stdout, stderr bytes.Buffer
			newExit := run(args, &stdout, &stderr)
			var report bundle.Report
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatalf("new report: %v\n%s", err, stderr.String())
			}
			// The released CLI predates this flag; only the new verifier gets it.
			oldArgs := make([]string, 0, len(args))
			for i := 0; i < len(args); i++ {
				if args[i] == "--require-cleaning-from" {
					i++
					continue
				}
				oldArgs = append(oldArgs, args[i])
			}
			oldCmd := exec.CommandContext(ctx, old, oldArgs...)
			oldOut, err := oldCmd.CombinedOutput()
			oldExit := 0
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					oldExit = ee.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			var oldReport bundle.Report
			if err := json.Unmarshal(oldOut, &oldReport); err != nil || oldReport.ExitCode != oldExit || oldExit > 2 {
				t.Fatalf("invalid old result: exit %d, %v\n%s", oldExit, err, oldOut)
			}
			if oldReport.CleaningSteps != 0 || oldReport.NotCountedCleaningSteps != 0 || oldReport.CleaningScope != "" {
				t.Fatal("baseline build contains post-1.1.0 report fields")
			}
			t.Logf("(new, old) = (%d, %d)", newExit, oldExit)
			if newExit == 1 && oldExit == 2 && genuineAlterations[c.Name] == "" {
				t.Errorf("new tampering accusation without an allowed authenticated contradiction\n%s", stdout.String())
			}
			if oldExit == 1 && newExit != 1 && genuineAlterations[c.Name] == "" {
				t.Errorf("new result weakens a detected alteration without an allowed reason")
			}
			if strings.HasPrefix(c.Name, "Cleaning-") {
				want, ok := cleaningExitPairs[c.Name]
				if !ok {
					t.Fatal("cleaning case lacks a literal compatibility expectation")
				}
				if got := [2]int{newExit, oldExit}; got != want {
					t.Errorf("exit pair = %v, want %v\nold report: %s", got, want, oldOut)
				}
			}
			// Historical no-entry controls and altered evidence preserve the old result.
			if (c.Name == "Cleaning-23-before-no-entry" || c.Name == "Cleaning-25-before-tampered-entry" || c.Name == "Cleaning-29-before-historical") && newExit != oldExit {
				t.Error("before-start result changed")
			}
		})
	}
}

// Literal per-case expectations, independent of the production predicate and
// corpus verdict formula. Present cleaning entries gain the new verification
// path even before the start; mixed bundles include after-start entries.
var cleaningExitPairs = map[string][2]int{
	"Cleaning-00-three":                                         {0, 2},
	"Cleaning-00-three-online":                                  {0, 2},
	"Cleaning-01-middle-removed":                                {1, 1},
	"Cleaning-02-type-rehashed":                                 {1, 1},
	"Cleaning-02-type-changed":                                  {1, 1},
	"Cleaning-03-request-swapped-rehashed":                      {1, 1},
	"Cleaning-03-request-swapped":                               {1, 1},
	"Cleaning-04-downgrade":                                     {2, 0},
	"Cleaning-04-downgrade-allow-unanchored":                    {2, 0},
	"Cleaning-05-zero-events":                                   {2, 2},
	"Cleaning-05-zero-events-allow-unanchored":                  {2, 2},
	"Cleaning-06-no-root":                                       {2, 2},
	"Cleaning-06-no-root-allow-unanchored":                      {2, 2},
	"Cleaning-07-mixed":                                         {0, 2},
	"Cleaning-08-missing-entry":                                 {2, 2},
	"Cleaning-09-stripped-full-chain":                           {1, 1},
	"Cleaning-10-gateway-conversation-binding":                  {1, 1},
	"Cleaning-11-gateway-no-conversation":                       {2, 2},
	"Cleaning-12-extra-claim":                                   {2, 2},
	"Cleaning-13-marker-label-mismatch":                         {1, 1},
	"Cleaning-14-anchored-wrong-type":                           {2, 2},
	"Cleaning-15-full-chain-seal":                               {2, 2},
	"Cleaning-16-partial-with-entry":                            {0, 2},
	"Cleaning-17-partial-downgrade":                             {2, 0},
	"Cleaning-18-partial-relabelled-with-entry":                 {2, 2},
	"Cleaning-19-partial-relabelled-downgrade":                  {2, 0},
	"Cleaning-19-partial-relabelled-downgrade-allow-unanchored": {2, 0},
	"Cleaning-20-historical-compatible":                         {2, 2},
	"Cleaning-21-historical-downgrade":                          {2, 0},
	"Cleaning-22-extra-claim-downgrade":                         {2, 0},
	"Cleaning-23-before-no-entry":                               {0, 0},
	"Cleaning-24-before-with-entry":                             {0, 2},
	"Cleaning-25-before-tampered-entry":                         {1, 1},
	"Cleaning-26-before-and-after":                              {0, 2},
	"Cleaning-27-at-start-no-entry":                             {2, 0},
	"Cleaning-28-unsigned-earlier-date":                         {2, 0},
	"Cleaning-29-before-historical":                             {0, 0},
	"Cleaning-30-counted-entry-removed":                         {1, 1},
	"Cleaning-31-malformed-entry-removed":                       {1, 1},
	"Cleaning-32-marker-less-extra-dsa-gateway":                 {2, 0},
	"Cleaning-32-marker-less-extra-dsa-sanitizer":               {2, 0},
	"Cleaning-32-marker-less-extra-dsa-bridge":                  {0, 0},
	"Cleaning-33-routed-partial-after-no-entry":                 {0, 0},
	"Cleaning-34-routed-partial-before-empty-audit":             {2, 2},
	"Cleaning-35-marker-plus-dsa-ai-no-entry":                   {2, 0},
}
