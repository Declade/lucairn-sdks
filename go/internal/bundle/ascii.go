package bundle

import (
	"fmt"
	"io"
	"unicode/utf8"
)

// ASCIIWriter returns a writer that passes ASCII bytes through and writes
// every other character as a Go-style escape (—, \U0001f600; a byte that
// is not valid UTF-8 as \xNN).
//
// The tool's own text is ASCII. This writer is the guarantee for everything
// else that can reach a terminal: file names, markers and error details that
// come out of the (untrusted) bundle. A default Windows console (code page
// 437/850) shows UTF-8 output that is piped or redirected as garbage
// ("PASS ΓÇö 7 files", T-1242), so the human-readable report and the usage
// text are ASCII-only. The JSON report is not passed through it.
func ASCIIWriter(w io.Writer) io.Writer { return &asciiWriter{w: w} }

type asciiWriter struct {
	w io.Writer
	// pending holds the first bytes of a character split across two writes.
	pending []byte
}

func (a *asciiWriter) Write(p []byte) (int, error) {
	n := len(p)
	if len(a.pending) > 0 {
		p = append(a.pending, p...)
		a.pending = nil
	}
	out := make([]byte, 0, len(p))
	for len(p) > 0 {
		if p[0] < utf8.RuneSelf {
			out = append(out, p[0])
			p = p[1:]
			continue
		}
		if !utf8.FullRune(p) {
			a.pending = append(a.pending, p...)
			break
		}
		r, size := utf8.DecodeRune(p)
		switch {
		case r == utf8.RuneError && size == 1:
			out = append(out, fmt.Sprintf(`\x%02x`, p[0])...)
		case r > 0xFFFF:
			out = append(out, fmt.Sprintf(`\U%08x`, r)...)
		default:
			out = append(out, fmt.Sprintf(`\u%04x`, r)...)
		}
		p = p[size:]
	}
	if _, err := a.w.Write(out); err != nil {
		return 0, err
	}
	return n, nil
}
