from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field

from lucairn.errors import VerifyCertificateFailureReason  # re-exported for convenience

__all__ = [
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
        api_key: DSA API key. Must match ``^dsa_[0-9a-f]{32}$``.
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
    """

    certificate_id: str
    request_id: str
    witness_key_id: str
    witness_asserted_issued_at: datetime
    witness_asserted_issued_at_iso: str
    anchor_status: VeilCertAnchorStatus
    overall_verdict: VeilVerdict
