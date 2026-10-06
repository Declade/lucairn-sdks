// Package bundle verifies a Lucairn evidence bundle (format
// lucairn-evidence-bundle, version 1): one zip per conversation, produced by
// the Lucairn account website, checked offline by cmd/lucairn-verify.
//
// PRD: specs/2026-10/prd-2026-10-06-evidence-bundle-export.md
// (Slice 1). The website writer is theveil-website
// src/lib/evidence-bundle/ — the two must agree on everything in this file.
package bundle

import (
	"crypto/sha256"
	"encoding/hex"
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
// make the result worse, never better — except dropping a certificate
// together with its manifest entry, which v1 cannot see (the per-conversation
// counter of Slice 2 closes that; the tool says so on every run).
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

// Completeness is the exporter's statement about whether every certificate
// of the conversation is in the bundle. Anything but "complete" makes the
// result INCOMPLETE.
type Completeness struct {
	State string `json:"state"`
	Note  string `json:"note,omitempty"`
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
