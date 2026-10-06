// Package bundle verifies a Lucairn evidence bundle (format
// lucairn-evidence-bundle, version 1): one zip per conversation, produced by
// the Lucairn account website, checked offline by cmd/lucairn-bundle-verify.
//
// PRD: specs/2026-10/prd-2026-10-06-evidence-bundle-export.md
// (Slice 1). The website writer is theveil-website
// src/lib/evidence-bundle/ — the two must agree on everything in this file.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Format identity.
const (
	FormatName       = "lucairn-evidence-bundle"
	FormatVersion    = 1
	KindConversation = "conversation"
)

// Fixed paths inside a v1 bundle.
const (
	PathManifest       = "manifest.json"
	PathReadme         = "README.txt"
	PathVerification   = "verification.json"
	PathReportExternal = "report-external.pdf"
	PathReportInternal = "report-internal.pdf"
	DirCertificates    = "certificates/"
)

// Size bounds (a bundle is untrusted input).
const (
	MaxBundleBytes      = 512 << 20
	MaxFileBytes        = 64 << 20
	MaxFiles            = 2000
	MaxCertificateBytes = 32 << 20
)

// certFileName is the only certificate file name shape v1 accepts.
var certFileName = regexp.MustCompile(`^certificates/[A-Za-z0-9._-]{1,128}\.json$`)

// RequiredPaths must be in every v1 bundle (and listed in the manifest);
// a bundle without one of them, or without any certificate, is TAMPERED.
var RequiredPaths = []string{PathManifest, PathReadme, PathReportExternal}

// manifestKeys is the exact (case-sensitive) key set of every object in
// manifest.json. Go's encoding/json matches keys case-INsensitively and takes
// the LAST of two case-variant keys, a JavaScript reader takes the first, so
// an exporter-side reader and this tool could read different values from one
// manifest. Any key not in this set — a case variant, a typo, an extra
// field — is a structural failure.
var manifestKeys = map[string]map[string]bool{
	"": {"format": true, "format_version": true, "bundle_kind": true, "conversation_id": true, "customer_id": true,
		"generated_at": true, "generator": true, "completeness": true, "certificates": true, "certificates_digest": true, "files": true},
	"completeness": {"listing": true, "note": true},
	"certificates": {"path": true, "request_id": true, "certificate_id": true},
	"files":        {"path": true, "sha256": true, "size": true},
}

// manifestKeyProblem returns a description of the first key in the decoded
// manifest that is not exactly a v1 manifest key, or "".
func manifestKeyProblem(doc map[string]any) string {
	check := func(level string, obj map[string]any) string {
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !manifestKeys[level][k] {
				where := "manifest"
				if level != "" {
					where = "manifest " + level
				}
				return fmt.Sprintf("%s has key %q, which is not a v1 manifest key (keys are case-sensitive)", where, k)
			}
		}
		return ""
	}
	if p := check("", doc); p != "" {
		return p
	}
	if c, ok := doc["completeness"].(map[string]any); ok {
		if p := check("completeness", c); p != "" {
			return p
		}
	}
	for _, level := range []string{"certificates", "files"} {
		arr, _ := doc[level].([]any)
		for _, e := range arr {
			if o, ok := e.(map[string]any); ok {
				if p := check(level, o); p != "" {
					return p
				}
			}
		}
	}
	return ""
}

// AllowedPath reports whether p may appear in a v1 bundle at all. Anything
// else (an audit/ folder, a nested path, a dot-dot) is a structural failure:
// v1 has no audit/ folder (Slice 2 adds it with format_version 2).
func AllowedPath(p string) bool {
	switch p {
	case PathManifest, PathReadme, PathVerification, PathReportExternal, PathReportInternal:
		return true
	}
	return certFileName.MatchString(p) && !strings.Contains(p, "..")
}

// Manifest is manifest.json. Everything in it is UNSIGNED: the tool treats
// it as the bundle's table of contents and checks every file against it, and
// it checks the conversation and customer ids it names against the SIGNED
// claim payloads of every certificate. A manifest edit can therefore only
// make the result worse, never better — except (G1) dropping a certificate
// together with its manifest entry, which v1 cannot see (the per-conversation
// counter of Slice 2 closes that), and (G3) replacing a report PDF,
// verification.json or README.txt together with its manifest digest: those
// files are covered by no signature. The tool says both on every run.
type Manifest struct {
	Format             string         `json:"format"`
	FormatVersion      int            `json:"format_version"`
	BundleKind         string         `json:"bundle_kind"`
	ConversationID     string         `json:"conversation_id"`
	CustomerID         string         `json:"customer_id"`
	GeneratedAt        string         `json:"generated_at"`
	Generator          string         `json:"generator"`
	Completeness       Completeness   `json:"completeness"`
	Certificates       []ManifestCert `json:"certificates"`
	CertificatesDigest string         `json:"certificates_digest"`
	Files              []ManifestFile `json:"files"`
}

// ListingExhausted is the only Completeness.Listing value that does not make
// the result INCOMPLETE.
const ListingExhausted = "exhausted"

// Completeness is the exporter's UNSIGNED statement about how its listing of
// the conversation's certificates ended. "exhausted" means the listing ran
// to its end; it is NOT a proof that every certificate is in the bundle
// (v1 cannot prove that — gap G1, closed by the Slice 2 counter). Anything
// else makes the result INCOMPLETE.
type Completeness struct {
	Listing string `json:"listing"`
	Note    string `json:"note,omitempty"`
}

// ManifestCert names one certificate file and the turn it must be.
type ManifestCert struct {
	Path          string `json:"path"`
	RequestID     string `json:"request_id"`
	CertificateID string `json:"certificate_id"`
}

// ManifestFile is one file's digest. Every file except manifest.json is
// listed exactly once.
type ManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// CertificatesDigest is the identity of the certificate set, printed by the
// tool and on the report's verify page so a reader can match the PDF to the
// certificates it describes:
//
//	sha256( "lucairn.evidence-bundle.certificates/v1\n" +
//	        for each certificate sorted by request_id:
//	          request_id + " " + hex(sha256(file bytes)) + "\n" )
//
// Same construction style as the conversation-evidence package hash
// (theveil-website src/lib/conversation-evidence/aggregate.ts
// computePackageHash): a domain tag, newline-joined fields, SHA-256.
func CertificatesDigest(fileSHA256ByRequestID map[string]string) string {
	ids := make([]string, 0, len(fileSHA256ByRequestID))
	for id := range fileSHA256ByRequestID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	h := sha256.New()
	h.Write([]byte("lucairn.evidence-bundle.certificates/v1\n"))
	for _, id := range ids {
		h.Write([]byte(id + " " + fileSHA256ByRequestID[id] + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}
