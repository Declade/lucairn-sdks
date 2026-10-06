package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/declade/lucairn-sdks/go/internal/bundle"
	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

// TestTamperCorpusOnBuiltBinary builds the real binary and runs the whole
// synthetic tamper corpus through it: every must-detect mutation exits 1 or
// 2, the clean bundles exit 0, and the documented v1 gaps exit 0 (measured,
// so the NOT COVERED list stays honest).
func TestTamperCorpusOnBuiltBinary(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "lucairn-bundle-verify")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-trimpath", "-o", bin, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	co, err := bundletest.NewCorpus()
	if err != nil {
		t.Fatal(err)
	}
	tsa := filepath.Join(dir, "tsa-root.pem")
	rekor := filepath.Join(dir, "rekor.pem")
	if err := os.WriteFile(tsa, co.World.TSARootPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rekor, co.World.RekorPEM(), 0o644); err != nil {
		t.Fatal(err)
	}
	flags := co.World.CLIFlags(tsa, rekor)
	detected := 0
	for _, c := range co.Cases {
		p := filepath.Join(dir, c.Name+".zip")
		if err := os.WriteFile(p, c.Zip, 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, append(append([]string{}, flags...), p)...)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		if bareAnchorPass.MatchString(out.String()) {
			t.Errorf("%s: the built binary printed a bare PASS for an anchor step\n%s", c.Name, out.String())
		}
		if c.Expect == bundletest.ExpectValid && !strings.Contains(out.String(), "LIMITATION: "+bundle.NotContentBoundReason) {
			t.Errorf("%s: clean run lacks the not-content-bound limitation", c.Name)
		}
		switch c.Expect {
		case bundletest.ExpectDetected:
			if code != 1 && code != 2 {
				t.Errorf("%s: mutation exit %d, want 1 or 2\n%s", c.Name, code, out.String())
			}
			detected++
		default:
			if code != 0 {
				t.Errorf("%s: exit %d, want 0\n%s", c.Name, code, out.String())
			}
		}
	}
	if detected < 12 {
		t.Fatalf("corpus has %d must-detect mutations, PRD requires >= 12", detected)
	}
}

var bareAnchorPass = regexp.MustCompile(`(?m)^\s+(timestamp|rekor)\s+PASS(\s+—|\s*$)`)

func TestRun_UsageAndVersion(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb); code != 2 {
		t.Fatalf("no args: exit %d, want 2", code)
	}
	if code := run([]string{"--version"}, &out, &errb); code != 0 {
		t.Fatalf("--version: exit %d", code)
	}
	out.Reset()
	if code := run([]string{"--print-trust-roots"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d") {
		t.Fatalf("--print-trust-roots: exit %d\n%s", code, out.String())
	}
	if code := run([]string{"--witness-key", "nope", "x.zip"}, &out, &errb); code != 2 {
		t.Fatalf("bad key flag: exit %d, want 2", code)
	}
	if code := run([]string{filepath.Join(t.TempDir(), "missing.zip")}, &out, &errb); code != 2 {
		t.Fatalf("missing file: exit %d, want 2", code)
	}
}
