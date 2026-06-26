//go:build ignore
// Regenerate canonical-json-nonascii-go-reference.hex.
//
// Usage: this file imports github.com/Declade/dual-sandbox-architecture/pkg/veil,
// so it must be run from within the dual-sandbox-architecture module (its
// go.mod is the only one that resolves that import path).
//
//	cd /path/to/dual-sandbox-architecture
//	go run /path/to/theveil-sdks/ts/src/verify-certificate/__fixtures__/gen-go-nonascii-reference.go \
//	  > /path/to/theveil-sdks/ts/src/verify-certificate/__fixtures__/canonical-json-nonascii-go-reference.hex
//
// MANDATORY determinism check before committing: run this twice on the same
// input and byte-compare. If outputs differ, Go's marshal path is non-
// deterministic for this input and the golden-hex test would become flaky.
// STOP, diagnose root cause, file a DSA issue — do NOT paper over by
// regenerating until it happens to match.
//
// Re-run whenever dual-sandbox-architecture/pkg/veil/canonical.go changes.
// On regen, confirm the diff between old and new hex matches the Go change.
//
// This file is build-tagged `ignore` so it never compiles into a Go build.
// It exists as documentation + a reproducible regeneration path.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Declade/dual-sandbox-architecture/pkg/veil"
)

func main() {
	_, thisFile, _, _ := runtime.Caller(0)
	inputPath := filepath.Join(filepath.Dir(thisFile), "canonical-json-nonascii-go-reference-input.json")

	f, err := os.Open(inputPath)
	if err != nil {
		fatalf("open input: %v", err)
	}
	defer f.Close()

	raw, err := io.ReadAll(f)
	if err != nil {
		fatalf("read input: %v", err)
	}

	// UseNumber so integer values survive the unmarshal round-trip
	// without going through float64.
	dec := json.NewDecoder(newBytesReader(raw))
	dec.UseNumber()
	var parsed map[string]any
	if err := dec.Decode(&parsed); err != nil {
		fatalf("parse input JSON: %v", err)
	}

	revived := reviveRawInts(parsed)

	out, err := veil.CanonicalJSON(revived.(map[string]any))
	if err != nil {
		fatalf("canonicalize: %v", err)
	}

	fmt.Println(hex.EncodeToString(out))
}

// reviveRawInts converts {"$rawInt": N} markers into json.Number values so
// veil.CanonicalJSON emits them as unquoted integers. Mirrors the TS side's
// reviveRawIntegers helper in canonicalJson.test.ts.
func reviveRawInts(v any) any {
	switch val := v.(type) {
	case map[string]any:
		if rawInt, ok := val["$rawInt"]; ok && len(val) == 1 {
			// rawInt is json.Number (string) — pass through unchanged.
			if num, ok := rawInt.(json.Number); ok {
				return num
			}
			// If unmarshalled as int-shaped float (shouldn't happen with
			// UseNumber), coerce.
			return json.Number(fmt.Sprintf("%v", rawInt))
		}
		out := make(map[string]any, len(val))
		for k, v := range val {
			out[k] = reviveRawInts(v)
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, v := range val {
			out[i] = reviveRawInts(v)
		}
		return out
	default:
		return v
	}
}

type bytesReader struct {
	b   []byte
	pos int
}

func newBytesReader(b []byte) *bytesReader { return &bytesReader{b: b} }

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
