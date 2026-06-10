package lucairn

import (
	"encoding/json"
	"time"
)

// VeilCertAnchorStatus names a value in the gateway's full-name protojson
// enum form for cert.anchor_status.status.
type VeilCertAnchorStatus string

const (
	AnchorStatusUnspecified VeilCertAnchorStatus = "ANCHOR_STATUS_UNSPECIFIED"
	AnchorStatusPending     VeilCertAnchorStatus = "ANCHOR_STATUS_PENDING"
	AnchorStatusAnchored    VeilCertAnchorStatus = "ANCHOR_STATUS_ANCHORED"
	AnchorStatusFailed      VeilCertAnchorStatus = "ANCHOR_STATUS_FAILED"
)

// VeilVerdict names a value in the protojson full-name form for
// cert.verification.overall_verdict.
type VeilVerdict string

const (
	VerdictUnspecified VeilVerdict = "VERDICT_UNSPECIFIED"
	VerdictVerified    VeilVerdict = "VERDICT_VERIFIED"
	VerdictPartial     VeilVerdict = "VERDICT_PARTIAL"
	VerdictFailed      VeilVerdict = "VERDICT_FAILED"
)

// VeilCompleteness names a value in the protojson full-name form for
// cert.verification.completeness.
type VeilCompleteness string

const (
	CompletenessUnspecified VeilCompleteness = "COMPLETENESS_UNSPECIFIED"
	CompletenessFull        VeilCompleteness = "COMPLETENESS_FULL"
	CompletenessPartial     VeilCompleteness = "COMPLETENESS_PARTIAL"
)

// VeilClaimType names a value in the protojson full-name form for
// cert.claims[*].claim_type.
type VeilClaimType string

const (
	ClaimTypeUnspecified        VeilClaimType = "CLAIM_TYPE_UNSPECIFIED"
	ClaimTypeTokenGenerated     VeilClaimType = "CLAIM_TYPE_TOKEN_GENERATED"
	ClaimTypePIISanitized       VeilClaimType = "CLAIM_TYPE_PII_SANITIZED"
	ClaimTypeInferenceCompleted VeilClaimType = "CLAIM_TYPE_INFERENCE_COMPLETED"
	ClaimTypeEventsRecorded     VeilClaimType = "CLAIM_TYPE_EVENTS_RECORDED"
)

// VeilClaim is one per-service claim carried by the certificate. Only
// fields covered by the witness signature are needed for v1 verify;
// opaque oneof payload variants (Bridge / Sanitizer / Inference / Audit)
// are surfaced as raw JSON for future arcs.
type VeilClaim struct {
	ClaimID          string          `json:"claim_id"`
	RequestID        string          `json:"request_id"`
	ServiceID        string          `json:"service_id"`
	ClaimType        VeilClaimType   `json:"claim_type"`
	DataSeen         []string        `json:"data_seen,omitempty"`
	DataNotSeen      []string        `json:"data_not_seen,omitempty"`
	CanonicalPayload string          `json:"canonical_payload"` // base64 of per-service canonical JSON
	Timestamp        string          `json:"timestamp"`         // RFC 3339 (nanosecond precision)
	Signature        string          `json:"signature"`         // base64 Ed25519 of CanonicalPayload
	Bridge           json.RawMessage `json:"bridge,omitempty"`
	Sanitizer        json.RawMessage `json:"sanitizer,omitempty"`
	Inference        json.RawMessage `json:"inference,omitempty"`
	Audit            json.RawMessage `json:"audit,omitempty"`
}

// VeilVerificationResult is the witness-asserted result of per-service
// checks. The SDK surfaces these verbatim — v1 does NOT independently
// re-run any of them.
type VeilVerificationResult struct {
	SignaturesValid          bool             `json:"signatures_valid"`
	Completeness             VeilCompleteness `json:"completeness"`
	MissingServices          []string         `json:"missing_services,omitempty"`
	TemporalConsistent       bool             `json:"temporal_consistent"`
	DataVisibilityConsistent bool             `json:"data_visibility_consistent"`
	IsolationVerified        bool             `json:"isolation_verified"`
	QIScore                  json.RawMessage  `json:"qi_score,omitempty"`
	OverallVerdict           VeilVerdict      `json:"overall_verdict"`
	// BYOK exempt: true when at least one dsa-ai claim in the chain
	// carried IsolationProbe = ISOLATION_PROBE_BYOK_EXEMPT, indicating
	// the gateway routed inference to a customer-supplied upstream
	// provider. When true, IsolationVerified is also true and the cert
	// is safe to render as VERIFIED. Default false keeps backward compat
	// with older certs that omit the field. NOT in the 7-key witness
	// signable; tamper-evidence is INDIRECT via the bridge claim's
	// bridge-signed canonical_payload.
	//
	// Cross-language semantic for older certs (no byok_exempt field on
	// the wire):
	//   - Go (this SDK): zero-value false with `json:"...,omitempty"` —
	//     the field is absent on JSON re-serialize.
	//   - Python: defaults to False after parse.
	//   - TypeScript: leaves the field as undefined (optional).
	// Customers writing cross-language code that round-trips this field
	// should prefer truthy checks (`if cert.Verification.ByokExempt`)
	// over strict equality, since the absent/false distinction is not
	// preserved across languages.
	ByokExempt bool `json:"byok_exempt,omitempty"`
}

// VeilAnchorStatusInfo is the anchor status sub-object. v1 surfaces
// Status; all other fields are informational.
type VeilAnchorStatusInfo struct {
	Status    VeilCertAnchorStatus `json:"status"`
	Attempts  *int                 `json:"attempts,omitempty"`
	LastError string               `json:"last_error,omitempty"`
	HumanNote string               `json:"human_note,omitempty"`
}

// VeilExternalAttestation is the opaque attestation block. v1 verify does
// NOT inspect these fields. External RFC 3161 timestamp + Sigstore Rekor
// transparency-log verification are out of scope for this release.
type VeilExternalAttestation struct {
	Timestamp       json.RawMessage `json:"timestamp,omitempty"`
	TransparencyLog json.RawMessage `json:"transparency_log,omitempty"`
	Notary          json.RawMessage `json:"notary,omitempty"`
}

// VeilCertificate is the protojson-shaped certificate body served by
// GET /api/v1/veil/certificate/{request_id}.
//
// Gateway marshaller:
//
//	protojson.MarshalOptions{ EmitUnpopulated: true, UseProtoNames: true }
//
// Field names are snake_case; enum values emit in full-name form.
//
// Unknown/additive fields are preserved via Go's default json.Unmarshal
// behaviour (fields not present in the struct are silently dropped —
// matches the thin-transport rule). When the gateway ships new fields in
// a future release, the SDK continues to unmarshal cleanly.
type VeilCertificate struct {
	CertificateID   string `json:"certificate_id"`
	RequestID       string `json:"request_id"`
	ProtocolVersion int    `json:"protocol_version"`

	// Signed-subset fields
	Claims       []VeilClaim            `json:"claims"`
	Verification VeilVerificationResult `json:"verification"`
	IssuedAt     string                 `json:"issued_at"` // RFC 3339

	// Not in signed subset — passed through / unused by v1
	FormalVerification json.RawMessage `json:"formal_verification,omitempty"`
	AuditIntegrity     json.RawMessage `json:"audit_integrity,omitempty"`
	PrivacyBudget      json.RawMessage `json:"privacy_budget,omitempty"`

	// Witness signature + identity
	WitnessSignature string `json:"witness_signature"` // base64 Ed25519 (64 bytes)
	WitnessKeyID     string `json:"witness_key_id"`

	// Opaque to v1
	Attestation  *VeilExternalAttestation `json:"attestation,omitempty"`
	AnchorStatus *VeilAnchorStatusInfo    `json:"anchor_status,omitempty"`

	// ClientID is the org-scoping metadata field (proto field 14, optional
	// string) added in W2A-B1. Bridge stamps `org_id` into its claim
	// canonical_payload; the witness assembler extracts it into the
	// certificate top-level as a *string mirror of the protojson shape:
	// nil renders as `null`; populated renders as a quoted JSON string.
	//
	// IMPORTANT (locked decision, SDK signable-versioning v3 chain):
	// ClientID is NOT part of the v2 signable (7 keys, UNCHANGED).
	// ClientID IS part of the v3 signable (13 keys). Tamper-evidence on
	// v2-only SDKs flows INDIRECTLY via the bridge claim's canonical_payload.
	// Source: dual-sandbox-architecture/services/veil-witness/internal/assembler/
	// assembler.go:131-160.
	ClientID *string `json:"client_id,omitempty"`

	// APIKeyID is the gateway API-key metadata field (proto field 15, optional
	// string) added in Phase B (PRD prd-2026-06-08-api-key-id-in-cert.md).
	// Format: "k_<base32_16>" (direct-mint) or "sync-<sha256[:32]>" (control-API-synced).
	// nil on older certs (pre Phase B deploy) and control-API-synced keys.
	// NOT in v2 signable (7 keys, UNCHANGED); IS in v3 signable (13 keys).
	APIKeyID *string `json:"api_key_id,omitempty"`

	// v3 dual-protocol fields (absent on legacy v2 certs).

	// SignableV2Signature is the base64-encoded Ed25519 signature over the
	// 7-key v2 signable map. Mirrors WitnessSignature byte-for-byte so
	// v0.5.x SDKs (which only know WitnessSignature) continue to verify
	// unchanged. Present only on certs signed by a v3-capable witness.
	SignableV2Signature string `json:"signable_v2_signature,omitempty"`

	// SignableV3Signature is the base64-encoded Ed25519 signature over the
	// 13-key v3 signable map. Present only when SignableProtocolVersionEmitted >= 3.
	SignableV3Signature string `json:"signable_v3_signature,omitempty"`

	// SignableProtocolVersionEmitted is the highest signable-protocol version
	// the witness emitted on this cert (proto field 18). 0 = absent (v2 cert).
	// 3 = dual-protocol cert carrying both v2 + v3 signatures. The SDK
	// dispatches to v3 verification when this is >= 3.
	SignableProtocolVersionEmitted int `json:"signable_protocol_version_emitted,omitempty"`
}

// GetClientID returns cert.ClientID dereferenced, or "" if the cert is
// nil or ClientID was not populated. Convenience accessor — callers who
// need to distinguish "field absent" from "field present but empty"
// should inspect ClientID directly.
func (c *VeilCertificate) GetClientID() string {
	if c == nil || c.ClientID == nil {
		return ""
	}
	return *c.ClientID
}

// VerifyCertificateKeys is the trust-root input to VerifyCertificate.
type VerifyCertificateKeys struct {
	WitnessKeyID string
	// WitnessPublicKey is raw 32-byte Ed25519 OR a base64 string encoding
	// those 32 bytes. NOT PEM SPKI. Malformed input surfaces as
	// CertificateError{ Reason: ReasonInvalidSignature }.
	WitnessPublicKey any

	// MinimumSignableVersion enforces a floor on the signable-protocol version
	// the verified certificate must use. Accepted values:
	//
	//   ""    (default) — backward-compatible behavior. v2 and v3 certs are
	//         both accepted. Downgrade attacks (v3-sig-present but version
	//         stripped) are still rejected via the default stripping guard.
	//
	//   "v3"  — strict mode. Returns CertificateError{Reason:
	//         ReasonSignableVersionInsufficient} if the resolved signable
	//         version is not "v3". Use this when the caller depends on the
	//         v3 witness-signed guarantee for api_key_id, client_id,
	//         byok_exempt, redaction_manifest_hash, sanitized_fields_body_hash,
	//         or tms_manifest_hash.
	//
	// Any other value is treated as "" (permissive). Future signable versions
	// will be added here as new named constants.
	//
	// NOTE: when SignableVersion == "v2", the fields listed above are NOT
	// covered by the witness signature; an attacker could tamper with them
	// without invalidating the signature. Callers relying on those fields for
	// access-control or audit decisions MUST set MinimumSignableVersion: "v3".
	MinimumSignableVersion string
}

// VerifyCertificateResult is returned from a successful VerifyCertificate.
//
// Both a parsed time.Time (ergonomic) and the raw ISO string (exact
// signed bytes, full nanosecond precision when present) are surfaced —
// matches TS `witnessAssertedIssuedAt: Date` + `witnessAssertedIssuedAtIso:
// string` and Python's equivalent two-field pair.
type VerifyCertificateResult struct {
	CertificateID string
	RequestID     string
	WitnessKeyID  string

	// WitnessAssertedIssuedAt is the witness-asserted issuance time parsed
	// from WitnessAssertedIssuedAtISO. NOT independently timestamped by an
	// external TSA — callers requiring trusted timestamps for freshness
	// gating should not rely on this field. External RFC 3161 verification
	// lands in a follow-up arc.
	//
	// Parsed via time.Parse(time.RFC3339Nano, ...). Zero-value if parse
	// fails (rare in practice — the Go assembler always emits
	// RFC3339Nano form); use WitnessAssertedIssuedAtISO as the
	// authoritative source.
	WitnessAssertedIssuedAt    time.Time
	WitnessAssertedIssuedAtISO string // raw RFC 3339 string as signed by witness

	AnchorStatus   VeilCertAnchorStatus
	OverallVerdict VeilVerdict

	// SignableVersion is "v2" when the witness signature was verified against
	// the 7-key v2 signable map, or "v3" when verified against the 13-key v3
	// map (PRD criterion #7 — SDK signable-versioning v3 chain).
	// "v3" is returned when cert.signable_protocol_version_emitted >= 3 AND
	// signable_v3_signature is present and valid.
	// "v2" is returned for all legacy certs and certs whose
	// signable_protocol_version_emitted < 3.
	//
	// IMPORTANT: when SignableVersion == "v2", the following fields are NOT
	// covered by the witness Ed25519 signature and MUST NOT be trusted for
	// security decisions without out-of-band corroboration:
	//   APIKeyID, ClientID, ByokExempt (on VeilCertificate.Verification),
	//   redaction_manifest_hash, sanitized_fields_body_hash, tms_manifest_hash.
	// Callers relying on any of these fields MUST set
	// VerifyCertificateKeys.MinimumSignableVersion = "v3".
	SignableVersion string

	// V3SignatureStripped is true when the certificate carries a non-empty
	// signable_v3_signature but signable_protocol_version_emitted was absent
	// or < 3, causing the pipeline to dispatch via the v2 path. This
	// combination is a hallmark of a downgrade stripping attack; by default
	// (no opt-out) the pipeline rejects such certs with
	// ReasonVersionDowngradeDetected before reaching this point. V3SignatureStripped
	// is therefore always false on a successful verification result — it is
	// surfaced here as a diagnostic field for callers that opt out of the
	// stripping guard (not recommended) and inspect the raw result.
	V3SignatureStripped bool
}

// -- Proxy request / response types --------------------------------------

// ProxyPIIAnnotation is a ground-truth annotation for proving_ground mode.
type ProxyPIIAnnotation struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}

// MessagesRequest is the /api/v1/proxy/messages payload.
type MessagesRequest struct {
	PromptTemplate string                          `json:"prompt_template"`
	Context        map[string]string               `json:"context"`
	Model          string                          `json:"model,omitempty"`
	MaxTokens      *int                            `json:"max_tokens,omitempty"`
	Temperature    *float64                        `json:"temperature,omitempty"`
	RelinkResponse *bool                           `json:"relink_response,omitempty"`
	Mode           string                          `json:"mode,omitempty"` // "live" | "proving_ground"
	ActivityID     string                          `json:"activity_id,omitempty"`
	GroundTruth    map[string][]ProxyPIIAnnotation `json:"ground_truth,omitempty"`
}

// ProxyVeilReceipt appears on both sync and async responses for
// pro/enterprise-tier keys with Veil hints enabled.
type ProxyVeilReceipt struct {
	Status         string `json:"status"` // "available" | "pending"
	CertificateURL string `json:"certificate_url"`
	SummaryURL     string `json:"summary_url"`
}

// MessagesResponse is the tagged union returned by Client.Messages.
// Discriminate via type switch:
//
//	switch r := resp.(type) {
//	case *ProxySyncResponse:
//	    // sync (200) terminal result
//	case *ProxyAcceptedResponse:
//	    // async (202) processing receipt — poll r.StatusURL
//	}
type MessagesResponse interface {
	isMessagesResponse()
}

// ProxySyncResponse is the sync (200 OK) terminal result.
type ProxySyncResponse struct {
	Status          string            `json:"status"` // "JOB_STATUS_COMPLETED" or "JOB_STATUS_FAILED"
	ModelUsed       string            `json:"model_used"`
	LatencyMs       int               `json:"latency_ms"`
	Result          json.RawMessage   `json:"result,omitempty"`
	DLPRedacted     *bool             `json:"dlp_redacted,omitempty"`
	Relinked        *bool             `json:"relinked,omitempty"`
	ErrorMessage    string            `json:"error_message,omitempty"`
	RequestID       string            `json:"request_id,omitempty"`
	ComplianceTrace json.RawMessage   `json:"compliance_trace,omitempty"`
	GroundTruthEval json.RawMessage   `json:"ground_truth_evaluation,omitempty"`
	Veil            *ProxyVeilReceipt `json:"veil,omitempty"`
	VeilEvidence    json.RawMessage   `json:"veil_evidence,omitempty"`
	Tracevault      json.RawMessage   `json:"tracevault,omitempty"`
}

func (*ProxySyncResponse) isMessagesResponse() {}

// ProxyAcceptedResponse is the async (202) processing receipt.
type ProxyAcceptedResponse struct {
	Status    string            `json:"status"` // always "processing"
	JobID     string            `json:"job_id"`
	RequestID string            `json:"request_id"`
	StatusURL string            `json:"status_url"`
	Veil      *ProxyVeilReceipt `json:"veil,omitempty"`
}

func (*ProxyAcceptedResponse) isMessagesResponse() {}

// -- Audit-export request / response types --------------------------------

// AuditEntry is a single audit event surfaced by the gateway's
// /api/v1/audit/export endpoint. Mirrors the gateway's audit.Entry
// shape at dual-sandbox-architecture/services/gateway/internal/audit/
// buffer.go:11-17 — same JSON tags so structural tests stay
// byte-equivalent across both sides.
type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	EventType string    `json:"event_type"`
	Actor     string    `json:"actor"`
	Details   string    `json:"details"`
	RequestID string    `json:"request_id,omitempty"`
}

// AuditExportOptions configures a ListAuditEvents call.
//
//   - Days: lookback window in days. Zero means "use the gateway
//     default" (30 days at the time of writing — see audit_export.go:21).
//     The gateway caps at 90 (audit_export.go:22) and rejects values
//     outside [1,90] with HTTP 400.
//   - EventType: filter to a single event_type. Zero means "all types".
type AuditExportOptions struct {
	Days      int
	EventType string
}

// AuditExportResponse is the gateway's response shape for
// /api/v1/audit/export. Field shape mirrors the inline JSON object
// constructed at dual-sandbox-architecture/services/gateway/internal/
// api/audit_export.go:91-99 (anonymous map[string]interface{}); the
// SDK gives it a typed struct here for ergonomic Go callers.
type AuditExportResponse struct {
	CustomerID  string       `json:"customer_id"`
	Tier        string       `json:"tier"`
	Period      string       `json:"period"`
	Events      []AuditEntry `json:"events"`
	TotalEvents int          `json:"total_events"`
	Source      string       `json:"source"`
}
