package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	lucairn "github.com/declade/lucairn-sdks/go"
	"github.com/declade/lucairn-sdks/go/internal/bundle"
	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

// TestCleaningOfflineCompatibility builds the released verifier from the
// immutable 1.1.0 sources (HEAD~1 of reviewed ebdff02), through a Go overlay.
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
			t.Fatalf("git %v: %v\n%s", args, err, out)
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
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOFLAGS=")
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
			oldCmd := exec.CommandContext(ctx, old, args...)
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
			t.Logf("(new, old) = (%d, %d)", newExit, oldExit)
			if newExit == 1 && oldExit == 2 && genuineAlterations[c.Name] == "" {
				t.Errorf("new tampering accusation without an allowed authenticated contradiction\n%s", stdout.String())
			}
			if newExit == 0 {
				assertRequiredCleaningAccepted(t, c.Zip, co.World, &report)
			}
		})
	}
}

// An independent oracle reads only the chain verifier's authenticated values.
// It does not consume certAudit or the corpus's expected exit, so mislabelling
// a downgrade VALID cannot silently opt it out of this regression assertion.
func assertRequiredCleaningAccepted(t *testing.T, data []byte, w *bundletest.World, report *bundle.Report) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	roots := w.Roots()
	services := map[string]any{}
	for id, key := range roots.ServiceKeys {
		services[id] = []byte(key)
	}
	required := 0
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "certificates/") || !strings.HasSuffix(f.Name, ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		ch, err := lucairn.VerifyCertificateChain(raw, lucairn.CertificateChainKeys{
			WitnessKeyID: bundletest.WitnessKeyID, WitnessPublicKey: []byte(roots.WitnessKeys[bundletest.WitnessKeyID]), ServicePublicKeys: services,
		})
		if err != nil || ch.Verified == nil || ch.Verdict == "FAILED" {
			t.Fatalf("VALID bundle has an unverified chain: %v", err)
		}
		counts := map[any]int{}
		marker := false
		for _, claim := range ch.Verified.Claims {
			v := claim.Values
			counts[v["/service_id"]]++
			marker = marker || (v["/service_id"] == "dsa-gateway" && v["/payload/cert_tier"] == "input-shield")
		}
		if !marker && !(counts["dsa-gateway"] == 1 && counts["dsa-sanitizer"] == 1 && counts["dsa-audit"] == 0) {
			continue
		}
		required++
		var doc struct {
			RequestID string `json:"request_id"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		counter, inclusion := false, false
		for _, step := range report.Steps {
			if step.Scope == doc.RequestID && step.Status == bundle.Pass {
				counter = counter || step.Name == bundle.StepAuditCounter
				inclusion = inclusion || step.Name == bundle.StepAuditInclusion
			}
		}
		if ch.SignedCertTier != "input_shield_two_signer" || len(ch.Verified.Claims) != 2 || !counter || !inclusion {
			t.Errorf("VALID cleaning-requiring certificate %s without a strictly accepted anchored entry", doc.RequestID)
		}
	}
	if required != report.CleaningSteps {
		t.Errorf("VALID requires %d accepted cleaning entries, report counted %d", required, report.CleaningSteps)
	}
}
