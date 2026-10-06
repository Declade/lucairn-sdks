package bundletest

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"time"

	"github.com/declade/lucairn-sdks/go/internal/bundle"
)

// Files is a bundle's content by path (manifest.json included once built).
type Files map[string][]byte

// Clone copies the map (byte slices are copied too).
func (f Files) Clone() Files {
	out := Files{}
	for k, v := range f {
		out[k] = append([]byte(nil), v...)
	}
	return out
}

// SyntheticPDF is a stand-in report (the corpus never parses PDFs; only the
// manifest digest covers them).
var SyntheticPDF = []byte("%PDF-1.4\n% synthetic report stand-in for the lucairn-bundle-verify corpus\n%%EOF\n")

// Spec describes one bundle.
type Spec struct {
	ConversationID string
	CustomerID     string
	Certs          []*Cert
	Listing        string // default bundle.ListingExhausted
	WithInternal   bool
	// Audit, when set, makes this a format-2 bundle with the three audit/
	// files of this evidence (T-1231 S2b).
	Audit *Evidence
}

// Build produces the files of a well-formed bundle: format 1, or format 2
// when s.Audit is set.
func Build(s Spec) Files {
	f := Files{
		bundle.PathReadme:         []byte("Synthetic evidence bundle for the lucairn-bundle-verify test corpus.\n"),
		bundle.PathReportExternal: SyntheticPDF,
		bundle.PathVerification:   []byte(`{"note":"informational export-time record (synthetic)"}` + "\n"),
	}
	if s.WithInternal {
		f[bundle.PathReportInternal] = append([]byte(nil), SyntheticPDF...)
	}
	var entries []bundle.ManifestCert
	for _, c := range s.Certs {
		p := bundle.DirCertificates + c.RequestID + ".json"
		f[p] = c.JSON
		entries = append(entries, bundle.ManifestCert{Path: p, RequestID: c.RequestID, CertificateID: c.CertificateID})
	}
	listing := s.Listing
	if listing == "" {
		listing = bundle.ListingExhausted
	}
	version := bundle.FormatVersion
	if s.Audit != nil {
		version = bundle.FormatVersionAudit
		s.Audit.WriteTo(f)
	}
	m := bundle.Manifest{
		Format: bundle.FormatName, FormatVersion: version, BundleKind: bundle.KindConversation,
		ConversationID: s.ConversationID, CustomerID: s.CustomerID,
		GeneratedAt:  time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Generator:    "bundletest (synthetic)",
		Completeness: bundle.Completeness{Listing: listing},
		Certificates: entries,
	}
	f.WriteManifest(m)
	return f
}

// LegacyManifest, when true, makes every manifest this package writes use
// the ROUND-1 shape (completeness.state "complete" | "partial" instead of
// completeness.listing). It exists ONLY for the RED-PROOF run of the corpus
// against the pre-fix binary (head 0811712b), which rejects the new field;
// the tests of the current tool never set it.
var LegacyManifest bool

// Manifest decodes manifest.json.
func (f Files) Manifest() bundle.Manifest {
	raw := f[bundle.PathManifest]
	if LegacyManifest {
		var g map[string]any
		if err := json.Unmarshal(raw, &g); err != nil {
			panic(err)
		}
		if c, ok := g["completeness"].(map[string]any); ok {
			if c["state"] == "complete" {
				c["listing"] = bundle.ListingExhausted
			} else {
				c["listing"] = c["state"]
			}
			delete(c, "state")
		}
		raw, _ = json.Marshal(g)
	}
	var m bundle.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		panic(err)
	}
	return m
}

func encodeManifest(m bundle.Manifest) []byte {
	b, _ := json.MarshalIndent(m, "", "  ")
	if !LegacyManifest {
		return b
	}
	var g map[string]any
	if err := json.Unmarshal(b, &g); err != nil {
		panic(err)
	}
	c := g["completeness"].(map[string]any)
	state := "partial"
	if c["listing"] == bundle.ListingExhausted {
		state = "complete"
	}
	delete(c, "listing")
	c["state"] = state
	b, _ = json.MarshalIndent(g, "", "  ")
	return b
}

// WriteManifest recomputes every digest (the "attacker re-hashes" step) and
// writes manifest.json.
func (f Files) WriteManifest(m bundle.Manifest) {
	delete(f, bundle.PathManifest)
	m.Files = nil
	paths := make([]string, 0, len(f))
	for p := range f {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		s := sha256.Sum256(f[p])
		m.Files = append(m.Files, bundle.ManifestFile{Path: p, SHA256: hex.EncodeToString(s[:]), Size: int64(len(f[p]))})
	}
	byReq := map[string]string{}
	for _, c := range m.Certificates {
		if b, ok := f[c.Path]; ok {
			s := sha256.Sum256(b)
			byReq[c.RequestID] = hex.EncodeToString(s[:])
		}
	}
	m.CertificatesDigest = bundle.CertificatesDigest(byReq)
	f[bundle.PathManifest] = encodeManifest(m)
}

// Rehash rewrites the manifest digests for the current file contents,
// keeping every other manifest field.
func (f Files) Rehash() {
	f.WriteManifest(f.Manifest())
}

// Zip serializes the files (sorted, deterministic, deflate).
func (f Files) Zip() []byte { return f.ZipWithDirs() }

// ZipWithDirs is Zip plus empty DIRECTORY entries (names ending in "/")
// written first — the shape a re-zipped folder or a crafted archive has.
func (f Files) ZipWithDirs(dirs ...string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	paths := make([]string, 0, len(f))
	for p := range f {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, d := range dirs {
		if _, err := zw.CreateHeader(&zip.FileHeader{Name: d, Method: zip.Store, Modified: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)}); err != nil {
			panic(err)
		}
	}
	for _, p := range paths {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: p, Method: zip.Deflate, Modified: time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)})
		if err != nil {
			panic(err)
		}
		if _, err := w.Write(f[p]); err != nil {
			panic(err)
		}
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}
