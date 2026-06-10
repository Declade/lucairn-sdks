export interface LucairnConfig {
  apiKey: string;
  baseUrl?: string;
  timeoutMs?: number;
  /**
   * Maximum response-body size (in bytes) the SDK will read before raising
   * {@link LucairnResponseValidationError} on a 2xx status (the body was not
   * consumable) or {@link LucairnHttpError} on a non-2xx status. Defends a
   * client against a misbehaving / hostile gateway streaming an unbounded
   * body that would otherwise OOM the process. Must be a positive finite
   * integer; defaults to 10 MiB. Mirrors Python `max_response_bytes` and Go
   * `WithMaxResponseBytes` (both default 10 MiB).
   */
  maxResponseBytes?: number;
}

// Legacy alias — pre-Stage-3 callers used `TheVeilConfig`. Scheduled for
// removal in @lucairn/sdk@1.1.0. The @deprecated JSDoc tag tells VS Code
// and other JSDoc-aware editors to render strikethrough on legacy usages.
/** @deprecated Use {@link LucairnConfig} instead. The TheVeilConfig alias will be removed in @lucairn/sdk@1.1.0. */
export type TheVeilConfig = LucairnConfig;

// Mirror of gateway proxyPIIAnnotation (ground-truth annotation for proving_ground mode).
// TODO(proxy-sync): keep in lockstep with
//   dual-sandbox-architecture/services/gateway/internal/api/proxy.go:35 (proxyPIIAnnotation).
export interface ProxyPIIAnnotation {
  type: string;
  value: string;
  start: number;
  end: number;
}

// Mirror of gateway proxyRequest — the split-knowledge /api/v1/proxy/messages payload.
// TODO(proxy-sync): keep in lockstep with
//   dual-sandbox-architecture/services/gateway/internal/api/proxy.go:46 (proxyRequest).
export interface ProxyRequest {
  prompt_template: string;
  context: Record<string, string>;
  model?: string;
  max_tokens?: number;
  temperature?: number;
  stream?: boolean;
  relink_response?: boolean;
  mode?: 'live' | 'proving_ground';
  activity_id?: string;
  ground_truth?: Record<string, ProxyPIIAnnotation[]>;
}

// ProxyMessagesRequest narrows ProxyRequest: streaming is not supported by the
// messages() method, so `stream: true` is a compile-time error until a future
// arc ships the SSE code path.
export type ProxyMessagesRequest = Omit<ProxyRequest, 'stream'> & {
  stream?: false;
};

// Per-call knobs for messages(). All optional; compose with the client's
// defaults at request time.
export interface MessagesOptions {
  // Caller-owned abort signal. If it fires, the caller's abort reason is
  // rethrown verbatim (not wrapped in LucairnTimeoutError).
  signal?: AbortSignal;
  // Per-call timeout in milliseconds. Overrides the client default for this
  // call only.
  timeoutMs?: number;
  // Per-call headers merged on top of client defaults. SDK-owned headers
  // (x-api-key, content-type) still win — this mirrors the Session 1 header
  // merge behaviour.
  headers?: Record<string, string>;
}

// Sandbox B terminal job statuses that the gateway forwards on the sync path.
// The set is small and stable — proxy.go only emits these two after
// pollForResult returns a completed job.
// TODO(proxy-sync): observed at
//   dual-sandbox-architecture/services/gateway/internal/api/proxy.go:713 and :931.
export type ProxyJobStatus = 'JOB_STATUS_COMPLETED' | 'JOB_STATUS_FAILED';

// Shared veil-receipt sub-object carried on both sync and async responses
// when the customer is pro/enterprise tier and veil hints are enabled. The
// inner `status` value differs between paths but the surface is identical.
// TODO(proxy-sync):
//   sync  — proxy.go:921 (status="available")
//   async — proxy_async.go:137 (status="pending")
export interface ProxyVeilReceipt {
  status: 'available' | 'pending';
  certificate_url: string;
  summary_url: string;
}

// Sync (200 OK) response — pollForResult returned a terminal job result and
// writeProxyResult assembled the body.
// TODO(proxy-sync): response assembly lives at
//   dual-sandbox-architecture/services/gateway/internal/api/proxy.go:740 onward.
export interface ProxySyncResponse {
  status: ProxyJobStatus;
  model_used: string;
  latency_ms: number;
  result?: unknown;
  dlp_redacted?: boolean;
  relinked?: boolean;
  error_message?: string;
  // Present only for pro/enterprise tiers when Veil hints are enabled on the
  // gateway. The value is the Bridge token-request scoped ID, not the
  // gateway's internal per-call request UUID used in audit/log lines.
  request_id?: string;
  compliance_trace?: Record<string, unknown>;
  ground_truth_evaluation?: Record<string, unknown>;
  veil?: ProxyVeilReceipt;
  veil_evidence?: Record<string, unknown>;
  tracevault?: Record<string, unknown>;
}

// Async (202 Accepted) response — pollForResult timed out; the job is still
// running. Callers must poll `status_url` until the job completes.
// TODO(proxy-sync): mirrors asyncProcessingResponse at
//   dual-sandbox-architecture/services/gateway/internal/api/proxy_async.go:128.
export interface ProxyAcceptedResponse {
  status: 'processing';
  job_id: string;
  request_id: string;
  status_url: string;
  veil?: ProxyVeilReceipt;
}

// Discriminated on `status`: the literal 'processing' is the async branch;
// a ProxyJobStatus is the sync branch. Narrow with a check on response.status.
export type ProxyResponse = ProxySyncResponse | ProxyAcceptedResponse;

// ---------------------------------------------------------------------------
// VeilCertificate — minimal type mirroring proto/veil/v1/veil.proto as served
// via protojson at GET /api/v1/veil/certificate/{request_id}. Only the fields
// this arc reads are modeled. Full fetch helper + complete type lands in
// session 2b-cert-fetch.
//
// TODO(proxy-sync): keep in lockstep with
//   dual-sandbox-architecture/proto/veil/v1/veil.proto (VeilCertificate).
//
// Gateway marshaller:
//   services/gateway/internal/api/veil.go uses
//   protojson.MarshalOptions{ EmitUnpopulated: true, UseProtoNames: true }.
//   UseProtoNames affects field names only; enum values emit in full-name
//   form (e.g. "ANCHOR_STATUS_ANCHORED", not "ANCHORED"). All enum unions
//   below use full-name form to match.
// ---------------------------------------------------------------------------

export type VeilCertAnchorStatus =
  | 'ANCHOR_STATUS_UNSPECIFIED'
  | 'ANCHOR_STATUS_PENDING'
  | 'ANCHOR_STATUS_ANCHORED'
  | 'ANCHOR_STATUS_FAILED';

export type VeilVerdict =
  | 'VERDICT_UNSPECIFIED'
  | 'VERDICT_VERIFIED'
  | 'VERDICT_PARTIAL'
  | 'VERDICT_FAILED';

export type VeilCompleteness =
  | 'COMPLETENESS_UNSPECIFIED'
  | 'COMPLETENESS_FULL'
  | 'COMPLETENESS_PARTIAL';

export type VeilClaimType =
  | 'CLAIM_TYPE_UNSPECIFIED'
  | 'CLAIM_TYPE_TOKEN_GENERATED'
  | 'CLAIM_TYPE_PII_SANITIZED'
  | 'CLAIM_TYPE_INFERENCE_COMPLETED'
  | 'CLAIM_TYPE_EVENTS_RECORDED';

export type VeilIsolationProbeStatus =
  | 'ISOLATION_PROBE_UNKNOWN'
  | 'ISOLATION_PROBE_VERIFIED'
  | 'ISOLATION_PROBE_BREACHED'
  | 'ISOLATION_PROBE_LOCKED'
  // BYOK-exempt: customer-provided upstream key path skips the
  // gateway-managed isolation probe. Surfaces alongside
  // verification.byok_exempt = true. See dual-sandbox-architecture proto
  // field 9 on VerificationResult.
  | 'ISOLATION_PROBE_BYOK_EXEMPT';

// Claim shape — carried so verifyCertificate can extract claim_ids in order.
// Other fields are unused by v1 verify but declared for future arcs.
export interface VeilClaim {
  claim_id: string;
  request_id: string;
  service_id: string;
  claim_type: VeilClaimType;
  data_seen: string[];
  data_not_seen: string[];
  canonical_payload: string; // base64 of per-service canonical JSON
  timestamp: string;         // RFC 3339 (nanosecond precision)
  signature: string;         // base64 Ed25519 of canonical_payload
  // proto oneof payload variants — surfaced opaquely, not typed for v1.
  bridge?: Record<string, unknown>;
  sanitizer?: Record<string, unknown>;
  inference?: Record<string, unknown>;
  audit?: Record<string, unknown>;
}

export interface VeilVerificationResult {
  signatures_valid: boolean;
  completeness: VeilCompleteness;
  missing_services: string[];
  temporal_consistent: boolean;
  data_visibility_consistent: boolean;
  isolation_verified: boolean;
  qi_score: unknown;
  overall_verdict: VeilVerdict;
  /**
   * BYOK-exempt verification flag. `true` indicates the customer brought
   * their own upstream-provider key, so the gateway-managed isolation
   * probe was intentionally skipped — `isolation_verified` is still `true`
   * and the verdict is still `VERDICT_VERIFIED`. Optional for backward
   * compat with older certs that omit the field. NOT part of the 7-key
   * witness signable; tamper-evidence is INDIRECT via the bridge claim's
   * bridge-signed canonical_payload (which IS in the signable via
   * `claims`). Proto field number 9 on VerificationResult.
   *
   * Cross-language semantic for older certs (no `byok_exempt` field on
   * the wire):
   *   - TypeScript (this SDK): leaves the field as `undefined` (optional).
   *   - Python: defaults to `False` after parse.
   *   - Go: zero-value `false` with `json:"...,omitempty"` (may be absent
   *     on serialize).
   * Customers writing cross-language code that round-trips this field
   * should prefer truthy checks (`if (cert.verification.byok_exempt)`)
   * over strict equality (`=== false`), since the absent/false
   * distinction is not preserved across languages.
   */
  byok_exempt?: boolean;
}

export interface VeilAnchorStatusInfo {
  status: VeilCertAnchorStatus;
  attempts?: number;
  last_error?: string;
  human_note?: string;
}

// Opaque attestation — v1 does not verify these fields. Notary sub-object is
// surfaced for informational parity with server output. External TSA + Rekor
// verification land in 2b-cert-strong once gateway issues
// Declade/dual-sandbox-architecture#43/#44 close.
export interface VeilExternalAttestation {
  timestamp?: Record<string, unknown> | null;
  transparency_log?: Record<string, unknown> | null;
  notary?: {
    provider: string;
    notary_signature: string;
    notary_public_key_id: string;
    checks_performed: string[];
    attested_at?: string | null;
  } | null;
}

export interface VeilCertificate {
  certificate_id: string;
  request_id: string;
  protocol_version: number;

  // Signed-subset fields
  claims: VeilClaim[];
  verification: VeilVerificationResult;
  issued_at: string; // RFC 3339

  // Not in signed subset — passed through / unused by v1
  formal_verification?: Record<string, unknown> | null;
  audit_integrity?: Record<string, unknown> | null;
  privacy_budget?: Record<string, unknown> | null;

  // Witness signature + identity
  witness_signature: string; // base64 Ed25519 (64 bytes)
  witness_key_id: string;

  // Opaque to v1; surfaced on the result with JSDoc caveats
  attestation?: VeilExternalAttestation | null;
  anchor_status?: VeilAnchorStatusInfo | null;

  /**
   * Client identifier (the issuing org_id) for client-side correlation.
   * Optional metadata only — NOT part of the v2 witness signable map; IS
   * part of the v3 signable. The tamper-evidence chain for org_id runs via
   * the bridge claim's canonical_payload (which IS in the witness signable
   * via `claims`), so a verifier that needs cryptographic certainty about
   * the issuing org should check `claims[bridge].canonical_payload` rather
   * than this top-level field.
   *
   * Source: proto/veil/v1/veil.proto:160 (`optional string client_id = 14`).
   * Set by the witness assembler from the bridge claim payload at
   * services/veil-witness/internal/assembler/assembler.go:131-155 and
   * marshalled with EmitUnpopulated:true, so a missing value renders as
   * `null` (NOT undefined) in the gateway response JSON.
   *
   * Shipped via PR #92 (W2A-B1), merge ce7894e8 on
   * dual-sandbox-architecture main.
   */
  client_id?: string | null;

  /**
   * API key identifier associated with the cert. Part of the v3 signable
   * map. Optional metadata on v2 certs. Format: `k_<base32_16>` for
   * direct-mint keys, `sync-<sha256[:32]>` for control-API-synced keys.
   *
   * Source: proto/veil/v1/veil.proto (`optional string api_key_id = 15`).
   * Shipped via PR #242. NOT in the 7-key v2 signable.
   */
  api_key_id?: string | null;

  /**
   * v2 signature — mirrors `witness_signature` byte-for-byte (the same
   * Ed25519 signing op over the 7-key v2 signable). Carried explicitly so
   * callers can distinguish v2-path verification from v3-path verification.
   *
   * Source: proto/veil/v1/veil.proto (`bytes signable_v2_signature = 379`).
   * Shipped via PR #247 (TMS SDK chain step 1).
   */
  signable_v2_signature?: string | null;

  /**
   * v3 signature — Ed25519 over the 13-key v3 signable map. Present on
   * certs emitted after witness PR #247. Absent on older certs (field
   * is not backfilled). The SDK uses this for v3 verification when
   * `signable_protocol_version_emitted >= 3`.
   *
   * Source: proto/veil/v1/veil.proto (`bytes signable_v3_signature = 380`).
   */
  signable_v3_signature?: string | null;

  /**
   * Protocol version of the signable that was emitted by the witness at
   * cert creation time. 3 = v3 dual-protocol cert (carries both v2 and v3
   * signatures). Absent / 0 on older certs → SDK falls back to v2.
   *
   * Source: proto/veil/v1/veil.proto (`int32 signable_protocol_version_emitted = 381`).
   */
  signable_protocol_version_emitted?: number | null;
}

// ---------------------------------------------------------------------------
// Audit export — GET /api/v1/audit/export
//
// AuditEntry mirrors services/gateway/internal/audit/buffer.go:11 (`type Entry
// struct`). Fields use snake_case wire names per the Go json tags. RequestID
// is `request_id,omitempty` on the Go side and may be missing.
//
// AuditExportResponse mirrors services/gateway/internal/api/audit_export.go:91
// (the response writeJSON map literal). The `period` string is rendered as
// "YYYY-MM-DD to YYYY-MM-DD" by audit_export.go:88-89,94. `source` is one of
// "audit_service", "audit_service+memory_buffer", "memory_buffer", or "none"
// (audit_export.go:195-209).
// ---------------------------------------------------------------------------

export interface AuditEntry {
  timestamp: string;       // RFC 3339 (Go time.Time JSON encoding)
  event_type: string;
  actor: string;
  details: string;
  request_id?: string;
}

export interface AuditExportResponse {
  customer_id: string;
  tier: string;
  period: string;          // "YYYY-MM-DD to YYYY-MM-DD"
  events: AuditEntry[];
  total_events: number;
  source: string;
}

// Per-call knobs for listAuditEvents(). All optional; the gateway is the
// truth source for tier-gating and eventType allowlists, so the SDK does NOT
// validate either client-side.
export interface ListAuditEventsOptions {
  // Lookback window in days. Server default 30, max 90 (rejected with 400 by
  // the gateway when out of range). Citation: audit_export.go:21-22.
  days?: number;
  // Filter by event_type. Maps to the `type` query parameter. Citation:
  // audit_export.go:75.
  eventType?: string;
  signal?: AbortSignal;
  timeoutMs?: number;
  headers?: Record<string, string>;
}

export interface VerifyCertificateKeys {
  witnessKeyId: string;
  witnessPublicKey: Uint8Array | string; // raw 32B OR base64
}

export interface VerifyCertificateResult {
  certificateId: string;
  requestId: string;
  witnessKeyId: string;

  /**
   * Witness-asserted issuance time as a JS Date, truncated to millisecond
   * precision. Taken from cert.issued_at (covered by the witness signature)
   * but JS Date drops sub-millisecond digits.
   *
   * NOT independently timestamped by an external TSA — external RFC 3161
   * verification lands in a follow-up arc (2b-cert-strong, tracked against
   * Declade/dual-sandbox-architecture#43). Callers requiring trusted
   * timestamps for freshness gating should not rely on this field.
   *
   * Use {@link VerifyCertificateResult.witnessAssertedIssuedAtIso} when
   * precision beyond milliseconds matters (audit-record reconciliation,
   * cross-service event ordering).
   */
  witnessAssertedIssuedAt: Date;

  /**
   * RFC 3339 timestamp string exactly as signed by the witness, preserving
   * full precision (nanoseconds when present). Use this field instead of
   * {@link VerifyCertificateResult.witnessAssertedIssuedAt} when precision
   * beyond milliseconds matters.
   *
   * Same chain-of-custody caveats as `witnessAssertedIssuedAt`: witness-
   * asserted, not externally timestamped.
   */
  witnessAssertedIssuedAtIso: string;

  /**
   * Gateway-reported anchor status, passed through verbatim. The SDK does
   * NOT currently verify anchor status independently; follow-up arc
   * 2b-cert-strong adds external verification. Upstream gateway reliability
   * bug tracked at Declade/dual-sandbox-architecture#42 — do not treat this
   * value as authoritative until that issue is closed.
   */
  anchorStatus: VeilCertAnchorStatus;

  /**
   * Witness-asserted overall verdict. Covered by the witness signature, but
   * the SDK does not independently re-run any of the five underlying checks
   * (signatures_valid, completeness, temporal_consistent,
   * data_visibility_consistent, isolation_verified). Surface-only; treat as
   * metadata.
   */
  overallVerdict: VeilVerdict;

  /**
   * Which signable protocol version was verified. `'v3'` when the cert
   * carries `signable_v3_signature` and `signable_protocol_version_emitted
   * >= 3`; `'v2'` for all other certs (legacy + dual-protocol certs where
   * the SDK fell back to v2).
   *
   * Criterion #7 from prd-2026-06-08-typed-message-schema-sanitizer-rewrite.
   */
  signableVersion: 'v2' | 'v3';
}
