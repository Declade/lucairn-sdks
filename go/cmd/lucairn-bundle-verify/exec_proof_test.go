package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/declade/lucairn-sdks/go/internal/bundle"
	"github.com/declade/lucairn-sdks/go/internal/bundle/bundletest"
)

// TestExecutionProofOnWitnessMintedCertificates (T-1231 S2a fix round, gate
// TRIM "execution proof"): certificates minted by the REAL witness code path
// — assembler + attestor against synthetic-but-genuine TSA/Rekor rails, in
// dual-sandbox-architecture's
// services/veil-witness/internal/attestor/binding_fixround_test.go — exported
// in the bundle JSON shape, packed into a bundle and run through the BUILT
// offline verifier. Skipped unless LUCAIRN_S2A_EXPORT_DIR points at that
// export (one sub-directory per certificate: certificate.json, meta.json,
// tsa-root.pem, rekor.pem). Synthetic keys and data only.
func TestExecutionProofOnWitnessMintedCertificates(t *testing.T) {
	root := os.Getenv("LUCAIRN_S2A_EXPORT_DIR")
	if root == "" {
		t.Skip("LUCAIRN_S2A_EXPORT_DIR not set (run the DSA attestor tests with it first)")
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
	for _, tc := range []struct {
		name, allow string
		wantBound   []string // steps that must print PASS (content-bound)
	}{
		{"bound", "", []string{"timestamp", "rekor"}},
		{"rekor-only", "--allow-unanchored", []string{"rekor"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := filepath.Join(root, tc.name)
			var meta struct {
				ConversationID string            `json:"conversation_id"`
				CustomerID     string            `json:"customer_id"`
				RequestID      string            `json:"request_id"`
				CertificateID  string            `json:"certificate_id"`
				WitnessKeyID   string            `json:"witness_key_id"`
				WitnessKey     string            `json:"witness_key"`
				ServiceKeys    map[string]string `json:"service_keys"`
				Cutover        string            `json:"binding_cutover"`
			}
			mb, err := os.ReadFile(filepath.Join(src, "meta.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(mb, &meta); err != nil {
				t.Fatal(err)
			}
			certJSON, err := os.ReadFile(filepath.Join(src, "certificate.json"))
			if err != nil {
				t.Fatal(err)
			}
			flags := []string{"--witness-key", meta.WitnessKeyID + "=" + meta.WitnessKey,
				"--tsa-root", filepath.Join(src, "tsa-root.pem"), "--rekor-key", filepath.Join(src, "rekor.pem"),
				"--require-binding-after", meta.Cutover}
			ids := make([]string, 0, len(meta.ServiceKeys))
			for id := range meta.ServiceKeys {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				flags = append(flags, "--service-key", id+"="+meta.ServiceKeys[id])
			}
			if tc.allow != "" {
				flags = append(flags, tc.allow)
			} else {
				flags = append(flags, "--require-anchors")
			}
			pack := func(doc []byte) string {
				var d map[string]any
				if err := json.Unmarshal(doc, &d); err != nil {
					t.Fatal(err)
				}
				c := &bundletest.Cert{RequestID: meta.RequestID, CertificateID: meta.CertificateID, JSON: doc, Doc: d}
				f := bundletest.Build(bundletest.Spec{ConversationID: meta.ConversationID, CustomerID: meta.CustomerID, Certs: []*bundletest.Cert{c}})
				p := filepath.Join(dir, tc.name+"-"+strings.ReplaceAll(t.Name(), "/", "_")+"-"+base64.RawURLEncoding.EncodeToString(doc[len(doc)-6:])+".zip")
				if err := os.WriteFile(p, f.Zip(), 0o644); err != nil {
					t.Fatal(err)
				}
				return p
			}
			runBin := func(zip string) (int, string) {
				cmd := exec.Command(bin, append(append([]string{}, flags...), zip)...)
				var out bytes.Buffer
				cmd.Stdout, cmd.Stderr = &out, &out
				err := cmd.Run()
				var ee *exec.ExitError
				if errors.As(err, &ee) {
					return ee.ExitCode(), out.String()
				} else if err != nil {
					t.Fatal(err)
				}
				return 0, out.String()
			}

			code, out := runBin(pack(certJSON))
			t.Logf("clean %s bundle: exit %d\n%s", tc.name, code, out)
			if code != 0 {
				t.Fatalf("the witness-minted %s certificate must verify VALID offline, exit %d", tc.name, code)
			}
			for _, step := range tc.wantBound {
				if !strings.Contains(out, "  "+padStep(step)+" "+bundle.ContentBoundLabel) {
					t.Errorf("%s: missing %q line", step, bundle.ContentBoundLabel)
				}
			}

			// Tamper 1: the recorded cert_hash (an input to H).
			var d map[string]any
			_ = json.Unmarshal(certJSON, &d)
			ts := d["attestation"].(map[string]any)["timestamp"].(map[string]any)
			h, _ := base64.StdEncoding.DecodeString(ts["cert_hash"].(string))
			h[0] ^= 1
			ts["cert_hash"] = base64.StdEncoding.EncodeToString(h)
			tampered, _ := json.Marshal(d)
			if code, out := runBin(pack(tampered)); code != 1 {
				t.Fatalf("edited cert_hash: exit %d, want 1\n%s", code, out)
			}
			// Tamper 2: the binding marker stripped to legacy (downgrade).
			_ = json.Unmarshal(certJSON, &d)
			d["attestation"].(map[string]any)["timestamp"].(map[string]any)["hash_algorithm"] = "SHA-256"
			stripped, _ := json.Marshal(d)
			if code, out := runBin(pack(stripped)); code != 1 {
				t.Fatalf("binding marker stripped: exit %d, want 1\n%s", code, out)
			}
		})
	}
}

func padStep(s string) string { return s + strings.Repeat(" ", 16-len(s)) }
