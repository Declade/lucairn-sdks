package lucairn

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// tsFixturesDir returns the path to the TS-side fixture directory the Go
// SDK tests share with the TS + Python suites. Tests assume the monorepo
// layout: <repo>/go → <repo>/ts/src/verify-certificate/__fixtures__.
func tsFixturesDir(t *testing.T) string {
	t.Helper()
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// cwd = <repo>/go; monorepo root one up.
	root := filepath.Join(cwd, "..")
	fixtures := filepath.Join(root, "ts", "src", "verify-certificate", "__fixtures__")
	info, err := os.Stat(fixtures)
	if err != nil || !info.IsDir() {
		t.Fatalf("expected TS fixtures at %s (run tests from <repo>/go): %v", fixtures, err)
	}
	return fixtures
}

func loadFixture(t *testing.T, name string) map[string]any {
	t.Helper()
	fixtures := tsFixturesDir(t)
	path := filepath.Join(fixtures, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("parse fixture %s: %v", name, err)
	}
	return out
}

func witnessKeypair(t *testing.T) map[string]string {
	t.Helper()
	for _, name := range []string{"test-witness-keypair.json", "witness-keypair.json"} {
		p := filepath.Join(tsFixturesDir(t), name)
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			var out map[string]string
			if err := json.Unmarshal(data, &out); err == nil {
				return out
			}
		}
	}
	t.Fatalf("no witness keypair fixture found")
	return nil
}

const validAPIKey = "dsa_0123456789abcdef0123456789abcdef"

// deepCopyMap is a convenience for tests that mutate a fixture-loaded
// map. JSON round-trip is the simplest way to deep-copy an arbitrary
// map[string]any; we only use it in tests.
func deepCopyMap(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("deep copy marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("deep copy unmarshal: %v", err)
	}
	return out
}
