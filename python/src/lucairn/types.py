from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator

from lucairn.errors import VerifyCertificateFailureReason  # re-exported for convenience

__all__ = [
    "AuditEntry",
    "AuditExportOptions",
    "AuditExportResponse",
    "MessagesOptions",
    "ProxyAcceptedResponse",
    "ProxyJobStatus",
    "ProxyMessagesRequest",
    "ProxyPIIAnnotation",
    "ProxyRequest",
    "ProxyResponse",
    "ProxySyncResponse",
    "ProxyVeilReceipt",
    "LucairnConfig",
    "VeilAnchorStatusInfo",
    "VeilCertAnchorStatus",
    "VeilCertificate",
    "VeilClaim",
    "VeilClaimType",
    "VeilCompleteness",
    "VeilExternalAttestation",
    "VeilIsolationProbeStatus",
    "VeilVerdict",
    "VeilVerificationResult",
    "VerifyCertificateFailureReason",
    "VerifyCertificateKeys",
    "VerifyCertificateResult",
]


# ---------------------------------------------------------------------------
# Constructor config — plain dataclass (locked decision 2026-04-20 §2).
# No runtime coercion; the client constructor validates each field explicitly
# so error messages are locatable.
# ---------------------------------------------------------------------------


@dataclass
class LucairnConfig:
    """Constructor configuration for :class:`lucairn.Lucairn`.

    Attributes:
        api_key: Lucairn API key (``lcr_live_...``) or legacy ``dsa_...`` key.
        base_url: Gateway base URL. Defaults to the hosted gateway.
            Must be ``https://`` for non-loopback hosts; ``http://`` is
            accepted only for ``localhost`` / ``127.0.0.1`` / ``::1`` /
            ``*.local`` to prevent cleartext api-key leakage.
        timeout: Default per-call timeout in seconds. Positive finite float.
            TS SDK equivalent is ``timeoutMs`` (milliseconds); Python uses
            seconds to match ``httpx`` / ``requests`` / ``openai-python`` /
            ``anthropic-python`` convention.
        max_response_bytes: Maximum response-body size the SDK will read
            from the gateway, in bytes. Responses exceeding this cap raise
            :class:`LucairnResponseValidationError` on a 2xx status (the
            body was not consumable) or :class:`LucairnHttpError` on a
            non-2xx status (the transport status is the dominant signal).
            The prefix of the body read before the cap was hit is
            preserved on the error's ``body`` attribute so callers can
            diagnose misbehaving gateways. Note: the prefix is UTF-8-
            decoded with ``errors='replace'``; when the cap slices into a
            multi-byte UTF-8 sequence, the truncated body may contain a
            Unicode replacement character (``\\ufffd``). Callers inspecting
            raw body text should account for this. Defaults to 10 MiB
            (10 * 1024 * 1024). Pro / enterprise callers expecting larger
            bodies should raise the cap explicitly.
    """

    api_key: str
    base_url: str | None = None
    timeout: float | None = None
    max_response_bytes: int | None = None


# ---------------------------------------------------------------------------
# Per-call options — plain dataclass; parallels TS MessagesOptions.
# v1 sync client does NOT expose a cancel / abort surface — timeout is the
# only way to bound a call. Cancel support arrives with the async client in
# a later arc (locked decision 2026-04-20 §3).
# ---------------------------------------------------------------------------


@dataclass
class MessagesOptions:
    """Per-call options for :meth:`Lucairn.messages` and related methods.

    Attributes:
        timeout: Per-call timeout in seconds, overrides client default for
            this call only. ``None`` uses the client default.
        headers: Per-call headers merged on top of client defaults. SDK-owned
            headers (``x-api-key``, ``content-type``) still win over caller
            overrides — same behaviour as the TS SDK.
    """

    timeout: float | None = None
    headers: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Proxy request types — mirrors of gateway proxy.go payloads.
# TODO(proxy-sync): keep in lockstep with
#   dual-sandbox-architecture/services/gateway/internal/api/proxy.go.
# ---------------------------------------------------------------------------


class ProxyPIIAnnotation(BaseModel):
    """Ground-truth annotation for ``proving_ground`` mode."""

    model_config = ConfigDict(extra="ignore")

    type: str
    value: str
    start: int
    end: int


ProxyMode = Literal["live", "proving_ground"]


class ProxyRequest(BaseModel):
    """Split-knowledge /api/v1/proxy/messages payload."""

    model_config = ConfigDict(extra="ignore")

    prompt_template: str
    context: dict[str, str]
    model: str | None = None
    max_tokens: int | None = None
    temperature: float | None = None
    stream: bool | None = None
    relink_response: bool | None = None
    mode: ProxyMode | None = None
    activity_id: str | None = None
    ground_truth: dict[str, list[ProxyPIIAnnotation]] | None = None


class ProxyMessagesRequest(ProxyRequest):
    """Narrows :class:`ProxyRequest`: streaming is not supported by
    :meth:`Lucairn.messages`, so ``stream=True`` is rejected at send time.
    """

    # The field itself is inherited; runtime rejection happens in
    # Lucairn.messages() by raising LucairnConfigError when stream is True.
    # Keeping it as bool | None mirrors the TS declaration
    # (`stream?: false`) which is a compile-time narrowing with no runtime
    # type guard either — the gateway simply ignores stream on the /messages
    # endpoint.


# ---------------------------------------------------------------------------
# Proxy response types — sync + async discriminated via `status`.
# ---------------------------------------------------------------------------


ProxyJobStatus = Literal["JOB_STATUS_COMPLETED", "JOB_STATUS_FAILED"]


class ProxyVeilReceipt(BaseModel):
    """Shared veil-receipt sub-object present on both sync and async responses
    when the customer is pro/enterprise tier and veil hints are enabled.
    """

    model_config = ConfigDict(extra="ignore")

    status: Literal["available", "pending"]
    certificate_url: str
    summary_url: str


class ProxySyncResponse(BaseModel):
    """Sync (200 OK) response — pollForResult returned a terminal job result."""

    model_config = ConfigDict(extra="ignore")

    status: ProxyJobStatus
    model_used: str
    # Default 0 aligns with the Go SDK's lenient ``validateProxySyncResponse``
    # — the gateway may legitimately emit 0 on sub-ms paths, and a gateway
    # that omits the field entirely should surface as a zero-valued field
    # rather than a shape-validation failure.
    latency_ms: int = 0
    result: Any | None = None
    dlp_redacted: bool | None = None
    relinked: bool | None = None
    error_message: str | None = None
    # Number of PII entities the sanitizer redacted on this request. Mirrors
    # the Anthropic-compatible /v1/messages path's
    # ``metadata.dsa_compliance.redaction_count``
    # (``dual-sandbox-architecture/services/gateway/internal/api/anthropic_types.go:331``)
    # and the OpenAI-compatible /v1/chat/completions
    # ``metadata.dsa_compliance.redaction_count``
    # (``…/openai_handler.go:944``). The proxy /api/v1/proxy/messages path
    # does not currently emit this field at the top level — when the gateway
    # promotes it, callers receive it automatically; until then this stays
    # ``None`` and consumers should treat that as "data not available on
    # this tier/path" rather than "zero redactions".
    redaction_count: int | None = None
    # Present only for pro/enterprise tiers when Veil hints are enabled.
    request_id: str | None = None
    compliance_trace: dict[str, Any] | None = None
    ground_truth_evaluation: dict[str, Any] | None = None
    veil: ProxyVeilReceipt | None = None
    veil_evidence: dict[str, Any] | None = None
    tracevault: dict[str, Any] | None = None


class ProxyAcceptedResponse(BaseModel):
    """Async (202 Accepted) response — pollForResult timed out; job still
    running. Callers must poll ``status_url`` until the job completes.
    """

    model_config = ConfigDict(extra="ignore")

    status: Literal["processing"]
    job_id: str
    request_id: str
    status_url: str
    veil: ProxyVeilReceipt | None = None


# Discriminated union. The client discriminates by inspecting body["status"]
# at parse time — "processing" → accepted; anything else → sync.
ProxyResponse = Union[ProxySyncResponse, ProxyAcceptedResponse]


# ---------------------------------------------------------------------------
# VeilCertificate — minimal type mirroring proto/veil/v1/veil.proto as served
# via protojson at GET /api/v1/veil/certificate/{request_id}.
#
# Gateway marshaller uses protojson.MarshalOptions{
#   EmitUnpopulated: true, UseProtoNames: true }. Field names are snake_case;
# enum values emit in full-name form (e.g. "ANCHOR_STATUS_ANCHORED").
# ---------------------------------------------------------------------------


VeilCertAnchorStatus = Literal[
    "ANCHOR_STATUS_UNSPECIFIED",
    "ANCHOR_STATUS_PENDING",
    "ANCHOR_STATUS_ANCHORED",
    "ANCHOR_STATUS_FAILED",
]

VeilVerdict = Literal[
    "VERDICT_UNSPECIFIED",
    "VERDICT_VERIFIED",
    "VERDICT_PARTIAL",
    "VERDICT_FAILED",
]

VeilCompleteness = Literal[
    "COMPLETENESS_UNSPECIFIED",
    "COMPLETENESS_FULL",
    "COMPLETENESS_PARTIAL",
]

VeilClaimType = Literal[
    "CLAIM_TYPE_UNSPECIFIED",
    "CLAIM_TYPE_TOKEN_GENERATED",
    "CLAIM_TYPE_PII_SANITIZED",
    "CLAIM_TYPE_INFERENCE_COMPLETED",
    "CLAIM_TYPE_EVENTS_RECORDED",
]

VeilIsolationProbeStatus = Literal[
    "ISOLATION_PROBE_UNKNOWN",
    "ISOLATION_PROBE_VERIFIED",
    "ISOLATION_PROBE_BREACHED",
    "ISOLATION_PROBE_LOCKED",
    # BYOK-exempt: customer-provided upstream key path skips the gateway-managed
    # isolation probe. Surfaces as ``isolation_verified=true`` +
    # ``byok_exempt=true`` on :class:`VeilVerificationResult`. See
    # dual-sandbox-architecture proto field number 9 on VerificationResult.
    "ISOLATION_PROBE_BYOK_EXEMPT",
]


class VeilClaim(BaseModel):
    """Per-service claim carried on the certificate. Only fields covered by
    the witness signature are needed for v1 verify; opaque oneof payload
    variants (bridge / sanitizer / inference / audit) are surfaced as
    :class:`dict` for future arcs.
    """

    model_config = ConfigDict(extra="ignore")

    claim_id: str
    request_id: str
    service_id: str
    claim_type: VeilClaimType
    data_seen: list[str] = Field(default_factory=list)
    data_not_seen: list[str] = Field(default_factory=list)
    canonical_payload: str  # base64 of per-service canonical JSON
    timestamp: str  # RFC 3339 (nanosecond precision)
    signature: str  # base64 Ed25519 of canonical_payload
    bridge: dict[str, Any] | None = None
    sanitizer: dict[str, Any] | None = None
    inference: dict[str, Any] | None = None
    audit: dict[str, Any] | None = None


class VeilVerificationResult(BaseModel):
    model_config = ConfigDict(extra="ignore")

    signatures_valid: bool
    completeness: VeilCompleteness
    missing_services: list[str] = Field(default_factory=list)
    temporal_consistent: bool
    data_visibility_consistent: bool
    isolation_verified: bool
    qi_score: Any | None = None
    overall_verdict: VeilVerdict
    # BYOK-exempt verification flag. ``True`` indicates the customer brought
    # their own upstream-provider key, so the gateway-managed isolation probe
    # was intentionally skipped — ``isolation_verified`` is still ``True`` and
    # the verdict is still ``VERDICT_VERIFIED``. Default ``False`` keeps
    # backward compat with older certs that omit the field. NOT part of the
    # 7-key witness signable; tamper-evidence is INDIRECT via the bridge
    # claim's bridge-signed canonical_payload (which IS in the signable via
    # ``claims``). Proto field number 9 on VerificationResult.
    #
    # Cross-language semantic for older certs (no ``byok_exempt`` field on
    # the wire):
    #   - Python (this SDK): defaults to ``False`` after parse.
    #   - TypeScript: leaves the field as ``undefined`` (optional).
    #   - Go: zero-value ``false`` with ``json:"...,omitempty"`` (may be
    #     absent on serialize).
    # Customers writing cross-language code that round-trips this field
    # should prefer truthy checks (``if cert.verification.byok_exempt``)
    # over strict equality (``=== false``), since the absent/false
    # distinction is not preserved across languages.
    byok_exempt: bool = False


class VeilAnchorStatusInfo(BaseModel):
    model_config = ConfigDict(extra="ignore")

    status: VeilCertAnchorStatus
    attempts: int | None = None
    last_error: str | None = None
    human_note: str | None = None


class VeilExternalAttestation(BaseModel):
    """Opaque attestation block. v1 verify does NOT inspect these fields.
    External RFC 3161 timestamp + Sigstore Rekor transparency-log
    verification are out of scope for this SDK release — see follow-up
    arc 2b-cert-strong once gateway issues #43/#44 close.
    """

    model_config = ConfigDict(extra="ignore")

    timestamp: dict[str, Any] | None = None
    transparency_log: dict[str, Any] | None = None
    notary: dict[str, Any] | None = None


class VeilCertificate(BaseModel):
    """Certificate retrieved from ``GET /api/v1/veil/certificate/{request_id}``.

    Uses ``extra="ignore"`` to honour the thin-transport rule: unknown fields
    from future gateway versions are silently dropped, mirroring the TS SDK
    pass-through behaviour. Shape validation for v1 happens inside
    :func:`verify_certificate` on the signed subset.
    """

    model_config = ConfigDict(extra="ignore")

    certificate_id: str
    request_id: str
    protocol_version: int

    # Signed-subset fields
    claims: list[VeilClaim] = Field(default_factory=list)
    verification: VeilVerificationResult
    issued_at: str  # RFC 3339

    # Not in signed subset — passed through / unused by v1
    formal_verification: dict[str, Any] | None = None
    audit_integrity: dict[str, Any] | None = None
    privacy_budget: dict[str, Any] | None = None

    # Witness signature + identity
    witness_signature: str  # base64 Ed25519 (64 bytes)
    witness_key_id: str

    # Opaque to v1
    attestation: VeilExternalAttestation | None = None
    anchor_status: VeilAnchorStatusInfo | None = None

    # Org-scoped correlation field added by W2A-B1 (PR #92, merged
    # 2026-05-01). Proto definition: ``optional string client_id = 14`` in
    # ``dual-sandbox-architecture/proto/veil/v1/veil.proto:160``. The
    # witness assembler extracts org_id from the bridge claim's
    # canonical_payload at
    # ``services/veil-witness/internal/assembler/assembler.go:131-155`` and
    # stamps it here. Field is NOT part of the v2 witness signable map but IS
    # promoted into the v3 signable (SDK signable-versioning v3 chain, PR #247).
    # Tamper evidence for v2: INDIRECT via bridge claim's bridge-signed
    # canonical_payload (in witness signable via ``claims``).
    client_id: str | None = None

    # API-key correlation field, Phase B (PR #242). Proto field 15.
    # Extracted from bridge claim's canonical_payload.payload["api_key_id"].
    # NOT in v2 signable; IS in v3 signable. Same tamper-evidence pattern as
    # client_id.
    api_key_id: str | None = None

    # Dual-protocol signature fields (SDK signable-versioning v3 chain, PR #247).
    # signable_v2_signature: mirrors witness_signature byte-for-byte for
    #   v0.5.x backward compat (same 7-key signed bytes).
    # signable_v3_signature: new 13-key signed bytes (v2 keys + 6 carry-forwards).
    # signable_protocol_version_emitted: int, value 3 on v3 certs. When absent
    #   (older certs) the SDK defaults to 0 and falls back to v2 path. A JSON
    #   ``null`` is coerced to 0 by the validator below — matching TS (``?? 0``)
    #   and Go (nil → 0). The gateway never emits null today, so this is a pure
    #   cross-language tolerance parity fix, not a behaviour change on real certs.
    signable_v2_signature: str | None = None
    signable_v3_signature: str | None = None
    signable_protocol_version_emitted: int = 0

    @field_validator("signable_protocol_version_emitted", mode="before")
    @classmethod
    def _coerce_null_signable_version_to_zero(cls, v: object) -> object:
        """Tolerate an explicit JSON ``null`` for the version field → 0.

        Parity with TS (``cert.signable_protocol_version_emitted ?? 0``) and Go
        (a nil/absent proto int defaults to 0). Pydantic would otherwise reject
        ``None`` for an ``int`` field as malformed. Absent (key missing) already
        hits the ``= 0`` default; this handler covers the explicit-``null`` case
        only. Any non-null value passes through to normal int validation
        (so a bad type like ``"three"`` still raises, unchanged).
        """
        if v is None:
            return 0
        return v


# ---------------------------------------------------------------------------
# verify_certificate inputs + outputs — plain dataclasses; they are not
# wire-serialized, so Pydantic buys us nothing for them.
# ---------------------------------------------------------------------------


@dataclass
class VerifyCertificateKeys:
    """Trust-root keys passed to :func:`verify_certificate`.

    Attributes:
        witness_key_id: The ``kid`` value expected on the certificate. If
            ``cert.witness_key_id`` does not match, verification fails with
            ``reason="witness_mismatch"``.
        witness_public_key: Raw 32-byte Ed25519 public key OR a base64
            string. The pipeline normalizes both forms.
    """

    witness_key_id: str
    witness_public_key: bytes | str


@dataclass
class VerifyCertificateResult:
    """Result of a successful :func:`verify_certificate` call.

    Attributes:
        certificate_id: Certificate ID, now verified to be covered by the
            witness signature.
        request_id: Request ID, same guarantee.
        witness_key_id: Key ID that signed the certificate.
        witness_asserted_issued_at: Witness-asserted issuance time as a
            datetime. NOT independently timestamped by an external TSA —
            external RFC 3161 verification lands in a follow-up arc.
            Callers requiring trusted timestamps should not rely on this.
        witness_asserted_issued_at_iso: RFC 3339 string exactly as signed
            (preserves nanosecond precision when present).
        anchor_status: Gateway-reported anchor status. The SDK does NOT
            currently verify anchor status independently.
        overall_verdict: Witness-asserted overall verdict.
        signable_version: The signable protocol version used for
            verification: ``'v2'`` for legacy 7-key path (verifies against
            ``witness_signature`` / ``signable_v2_signature``), ``'v3'``
            for new 13-key path (verifies against ``signable_v3_signature``).
            SDK signable-versioning v3 chain (PR #247 + this SDK release).

            SECURITY NOTE: when ``signable_version == 'v2'``, the fields
            ``api_key_id``, ``client_id``, ``byok_exempt``, and the sanitizer
            hash fields (``redaction_manifest_hash``, ``sanitized_fields_body_hash``,
            ``tms_manifest_hash``) are NOT covered by the witness signature.
            Callers that rely on those fields for security decisions MUST
            require ``signable_version == 'v3'`` — e.g. pass
            ``minimum_signable_version='v3'`` to :func:`verify_certificate`.
        v3_signature_stripped: ``True`` when the certificate carried a
            ``signable_v3_signature`` but verification fell back to the v2
            path (e.g. because ``signable_protocol_version_emitted`` was
            absent or < 3). ``False`` in all other cases.

            This flag is set only when strict-mode
            (``minimum_signable_version='v3'``) is NOT in use — strict mode
            raises :class:`~lucairn.errors.LucairnCertificateError` with
            ``reason='version_downgrade_detected'`` before the v2 path is
            taken, so the result object is never constructed.

            Non-strict callers can inspect this field to detect a potential
            downgrade without failing hard.
    """

    certificate_id: str
    request_id: str
    witness_key_id: str
    witness_asserted_issued_at: datetime
    witness_asserted_issued_at_iso: str
    anchor_status: VeilCertAnchorStatus
    overall_verdict: VeilVerdict
    signable_version: str = "v2"
    v3_signature_stripped: bool = False


# ---------------------------------------------------------------------------
# Audit export — GET /api/v1/audit/export
# Citations:
#   - Handler: dual-sandbox-architecture/services/gateway/internal/api/audit_export.go:60-100
#   - Auth: API-key (authenticateAuditProfile), tier-gated (503 with
#     `audit_export_unavailable` if not enabled)
#   - Query params: days (default 30, max 90), type (optional)
#   - Entry shape: dual-sandbox-architecture/services/gateway/internal/audit/buffer.go:11-17
# ---------------------------------------------------------------------------


@dataclass
class AuditExportOptions:
    """Per-call options for :meth:`Lucairn.list_audit_events`.

    Attributes:
        days: Lookback window in days; gateway default is 30 if omitted,
            maximum is 90 (per ``audit_export.go:21-22``). Values outside
            ``1..90`` are rejected by the gateway with 400.
        type: Restrict to a specific event type; ``None`` returns all
            event types.
        timeout: Per-call timeout in seconds; ``None`` uses the client
            default. Same semantics as :class:`MessagesOptions.timeout`.
        headers: Per-call headers merged on top of client defaults; same
            semantics as :class:`MessagesOptions.headers`.
    """

    days: int | None = None
    type: str | None = None
    timeout: float | None = None
    headers: dict[str, str] = field(default_factory=dict)


class AuditEntry(BaseModel):
    """A single audit event row, mirroring the gateway's
    ``audit.Entry`` Go struct
    (``services/gateway/internal/audit/buffer.go:11-17``):

        type Entry struct {
            Timestamp time.Time `json:"timestamp"`
            EventType string    `json:"event_type"`
            Actor     string    `json:"actor"`
            Details   string    `json:"details"`
            RequestID string    `json:"request_id,omitempty"`
        }

    Uses ``extra="ignore"`` so future gateway-side field additions do
    not break this SDK.
    """

    model_config = ConfigDict(extra="ignore")

    timestamp: str  # RFC 3339 (Go time.Time renders as a string in JSON)
    event_type: str
    actor: str
    details: str
    # Go's `omitempty` means an empty RequestID is dropped from the JSON
    # entirely; this SDK accepts both that case and an explicit null.
    request_id: str | None = None


class AuditExportResponse(BaseModel):
    """Response body of ``GET /api/v1/audit/export``
    (``audit_export.go:91-99``)."""

    model_config = ConfigDict(extra="ignore")

    customer_id: str
    tier: str
    period: str  # "YYYY-MM-DD to YYYY-MM-DD"
    events: list[AuditEntry] = Field(default_factory=list)
    total_events: int
    source: str
