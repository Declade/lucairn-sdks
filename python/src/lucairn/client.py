"""TheVeil Python SDK client.

Port of theveil-sdks/ts/src/client.ts. Behavioural-parity with TS at the
observable level; surface adapts to Python idiom (seconds not milliseconds,
snake_case, no AbortSignal).
"""

from __future__ import annotations

import json as _json
import math
import re
from typing import Any
from urllib.parse import quote, urlparse

import httpx
from pydantic import TypeAdapter, ValidationError

from lucairn.errors import (
    TheVeilConfigError,
    TheVeilError,
    TheVeilHttpError,
    TheVeilResponseValidationError,
    TheVeilTimeoutError,
)
from lucairn.types import (
    MessagesOptions,
    ProxyAcceptedResponse,
    ProxyMessagesRequest,
    ProxyResponse,
    ProxySyncResponse,
    TheVeilConfig,
    VeilCertificate,
    VerifyCertificateKeys,
    VerifyCertificateResult,
)
from lucairn.verify_certificate.pipeline import (
    verify_certificate as _verify_certificate_impl,
)

__all__ = ["TheVeil"]


_API_KEY_PATTERN = re.compile(r"^dsa_[0-9a-f]{32}$")

# Default points at the hosted gateway for solo-dev tier.
# Enterprise self-hosters must pass base_url explicitly.
_DEFAULT_BASE_URL = "https://gateway.dsaveil.io"

# 30 seconds, matching TS DEFAULT_TIMEOUT_MS = 30_000.
_DEFAULT_TIMEOUT_S = 30.0

# 10 MiB — deliberately generous; certificates are typically <50 KB and
# messages responses rarely exceed 1 MB. The cap exists as a DoS backstop
# against a malicious or misbehaving gateway returning a pathologically
# large body, not as a product constraint. Callers expecting larger bodies
# can raise it via TheVeilConfig.max_response_bytes.
_DEFAULT_MAX_RESPONSE_BYTES = 10 * 1024 * 1024


_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


def _normalize_base_url(raw: str) -> str:
    try:
        parsed = urlparse(raw)
    except Exception as exc:
        raise TheVeilConfigError(f"Invalid base_url: {raw}") from exc
    if parsed.scheme not in ("http", "https"):
        raise TheVeilConfigError(
            f"base_url must use http or https, got: {parsed.scheme or '<empty>'}"
        )
    if not parsed.netloc:
        raise TheVeilConfigError(f"Invalid base_url: {raw}")
    # Security: reject ``http://`` outside loopback / mDNS-local hosts so a
    # misconfigured base_url cannot silently ship the api_key across a
    # network in cleartext. Enterprise self-hosters binding to localhost
    # over HTTP stay allowed; anyone intending a non-loopback production
    # endpoint must use https://.
    if parsed.scheme == "http":
        host = (parsed.hostname or "").lower()
        if host not in _LOOPBACK_HOSTS and not host.endswith(".local"):
            raise TheVeilConfigError(
                f"base_url must use https:// for non-loopback hosts; got http://{host}"
            )
    return raw.rstrip("/")


def _validate_timeout_s(value: float, source: str) -> float:
    """Port of TS validateTimeoutMs. Unit differs (seconds, not ms); validator
    shape identical: rejects 0, negative, NaN, +/-Infinity."""

    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise TheVeilConfigError(
            f"Invalid {source}: {value!r} — must be a positive finite number"
        )
    f = float(value)
    if not math.isfinite(f) or f <= 0:
        raise TheVeilConfigError(
            f"Invalid {source}: {value} — must be a positive finite number"
        )
    return f


class TheVeil:
    """Synchronous client for The Veil privacy-preserving AI gateway.

    Example:
        from lucairn import TheVeil, TheVeilConfig

        client = TheVeil(TheVeilConfig(api_key="dsa_" + "0" * 32))
        cert = client.get_certificate("req_abc123")
        result = client.verify_certificate(cert, keys)
    """

    def __init__(self, config: TheVeilConfig) -> None:
        # Validate every constructor input up front — same philosophy as the
        # TS client, where early rejection beats late-fail surprises inside
        # _request.
        if not isinstance(config, TheVeilConfig):
            raise TheVeilConfigError(
                "TheVeil() requires a TheVeilConfig instance"
            )
        if not isinstance(config.api_key, str) or not _API_KEY_PATTERN.fullmatch(
            config.api_key
        ):
            raise TheVeilConfigError(
                'Invalid api_key — expected format "dsa_" followed by 32 '
                "lowercase hex characters"
            )

        raw_base_url = config.base_url if config.base_url is not None else _DEFAULT_BASE_URL
        if not isinstance(raw_base_url, str):
            raise TheVeilConfigError(
                f"Invalid base_url: {raw_base_url!r} — must be a string"
            )
        base_url = _normalize_base_url(raw_base_url)

        if config.timeout is None:
            timeout_s = _DEFAULT_TIMEOUT_S
        else:
            timeout_s = _validate_timeout_s(config.timeout, "timeout")

        if config.max_response_bytes is None:
            max_response_bytes = _DEFAULT_MAX_RESPONSE_BYTES
        else:
            if (
                not isinstance(config.max_response_bytes, int)
                or isinstance(config.max_response_bytes, bool)
                or config.max_response_bytes <= 0
            ):
                raise TheVeilConfigError(
                    f"Invalid max_response_bytes: {config.max_response_bytes!r} "
                    "— must be a positive int"
                )
            max_response_bytes = config.max_response_bytes

        # API key stored on a name-mangled private attribute. Python has no
        # JS-style hard private fields, but ``__api_key`` triggers name
        # mangling (``_TheVeil__api_key``) which keeps the credential out
        # of casual ``vars(client)`` / ``__dict__`` access paths. Not a
        # security boundary — Python has no such primitive — but matches
        # the TS spirit of "not on the public surface."
        self.__api_key = config.api_key
        self.base_url = base_url
        self.timeout = timeout_s
        self.max_response_bytes = max_response_bytes

    # -- Public API ----------------------------------------------------------

    def messages(
        self,
        params: ProxyMessagesRequest | dict[str, Any],
        options: MessagesOptions | None = None,
    ) -> ProxyResponse:
        """Call ``POST /api/v1/proxy/messages``.

        Returns a :class:`ProxySyncResponse` (sync 200) or
        :class:`ProxyAcceptedResponse` (async 202 processing). Callers
        discriminate via ``response.status == "processing"``.
        """

        if isinstance(params, dict):
            try:
                params = ProxyMessagesRequest.model_validate(params)
            except ValidationError as exc:
                raise TheVeilConfigError(f"Invalid messages params: {exc}") from exc
        elif not isinstance(params, ProxyMessagesRequest):
            raise TheVeilConfigError(
                "messages() params must be a ProxyMessagesRequest or dict"
            )
        if params.stream is True:
            raise TheVeilConfigError(
                "messages() does not support stream=True — use a future streaming "
                "API once available"
            )

        body_json = params.model_dump_json(exclude_none=True)
        status, body, raw_text = self._request(
            path="/api/v1/proxy/messages",
            method="POST",
            body=body_json,
            options=options,
        )
        return _parse_proxy_response(status, body, raw_text)

    def verify_certificate(
        self,
        cert: VeilCertificate | dict[str, Any],
        keys: VerifyCertificateKeys,
    ) -> VerifyCertificateResult:
        """Verify a Veil Certificate's witness Ed25519 signature.

        See :func:`theveil.verify_certificate.verify_certificate` for the
        full failure-reason list and key-format conventions. External RFC
        3161 timestamp + Sigstore Rekor transparency-log verification are
        out of scope for this SDK release.
        """

        return _verify_certificate_impl(cert, keys)

    def get_certificate(
        self,
        request_id: str,
        options: MessagesOptions | None = None,
    ) -> VeilCertificate:
        """Fetch a Veil Certificate by ``request_id``.

        Calls ``GET /api/v1/veil/certificate/{request_id}``. The happy-path
        return is narrowly :class:`VeilCertificate`; the gateway's 202
        pending wrapper (certificate not yet assembled, or unknown
        ``request_id`` — the gateway does not distinguish) surfaces as
        :class:`TheVeilHttpError` with ``status=202`` and ``body`` holding
        ``{"status": "pending", "retry_after_seconds": 30, ...}`` so
        callers get a narrow happy-path type and an explicit retry signal.

        No auto-verification. Chain :meth:`verify_certificate` explicitly
        if you want witness-signature proof.
        """

        if not isinstance(request_id, str):
            raise TheVeilConfigError(
                f"request_id must be str, got {type(request_id).__name__}"
            )
        # quote(..., safe="") URL-encodes slashes, question marks, and every
        # other special character — defense in depth against path injection.
        # The gateway's path extractor tolerates unencoded slashes but the
        # SDK should never emit raw `..` or unescaped separators.
        encoded = quote(request_id, safe="")

        status, body, raw_text = self._request(
            path=f"/api/v1/veil/certificate/{encoded}",
            method="GET",
            body=None,
            options=options,
        )

        if status == 202:
            raise TheVeilHttpError(
                "Veil certificate is not yet assembled; retry after the indicated delay.",
                status=status,
                body=body,
            )

        try:
            return VeilCertificate.model_validate(body)
        except ValidationError as exc:
            # 2xx-but-wrong-shape is NOT an HTTP error — surface via the
            # dedicated response-validation class so callers can branch on
            # "transport failed (TheVeilHttpError)" vs "body doesn't look
            # like a VeilCertificate (TheVeilResponseValidationError)".
            #
            # When the parsed body is None (literal JSON null response),
            # fall back to the raw text ("null") so callers can distinguish
            # "gateway sent null" from "error body not populated."
            effective_body = raw_text if body is None else body
            raise TheVeilResponseValidationError(
                "Response body failed to deserialize as VeilCertificate",
                body=effective_body,
                cause=exc,
            ) from exc

    # -- Transport primitive -------------------------------------------------

    def _request(
        self,
        *,
        path: str,
        method: str,
        body: str | None,
        options: MessagesOptions | None,
    ) -> tuple[int, Any, str]:
        """Execute a single HTTP request and return ``(status, body, raw_text)``.

        Mirror of TS ``request<T>``. ``body`` is returned as parsed JSON
        when the response text is non-empty and parses as JSON; otherwise
        the raw text. ``raw_text`` is the full pre-parse response as a
        UTF-8 string (lenient-decoded with ``errors='replace'``) — callers
        fall back to this when the parsed body is ``None`` so the error
        surface can preserve the "gateway sent null / empty" signal
        without being confused with "SDK forgot to set .body".
        Non-2xx responses raise :class:`TheVeilHttpError`. A timeout
        raises :class:`TheVeilTimeoutError`. Other transport failures
        raise :class:`TheVeilError` with ``__cause__`` set.

        The 2xx happy-path body passes through without shape validation —
        thin-transport rule (matches TS SDK). Callers doing meaningful
        work on the body (e.g. :meth:`get_certificate`) run their own
        Pydantic coercion afterwards.
        """

        # Per-call timeout override — validated with constructor strictness.
        if options is not None and options.timeout is not None:
            timeout_s = _validate_timeout_s(options.timeout, "options.timeout")
        else:
            timeout_s = self.timeout

        # Header merge: caller-supplied keys are lowercased for idempotency,
        # then SDK-owned keys overwrite.
        merged: dict[str, str] = {}
        if options is not None and options.headers:
            for k, v in options.headers.items():
                if not isinstance(k, str) or not isinstance(v, str):
                    raise TheVeilConfigError(
                        "options.headers must be a dict[str, str]"
                    )
                merged[k.lower()] = v
        merged["x-api-key"] = self.__api_key
        merged["content-type"] = "application/json"

        url = f"{self.base_url}{path if path.startswith('/') else '/' + path}"

        status_code: int
        reason_phrase: str
        raw_bytes: bytes
        try:
            with httpx.Client(timeout=httpx.Timeout(timeout_s)) as client:
                with client.stream(
                    method=method,
                    url=url,
                    headers=merged,
                    content=body,
                ) as response:
                    status_code = response.status_code
                    reason_phrase = response.reason_phrase
                    # Stream + accumulate so a 10 GB body can't OOM the
                    # client. Buffer up to exactly self.max_response_bytes;
                    # any byte beyond that triggers over_cap = True. Preserve
                    # the cap-sized prefix even when the first chunk arrives
                    # larger than the cap (common with respx / httptest or
                    # small-body responses from a streaming gateway).
                    accumulated = 0
                    chunks: list[bytes] = []
                    over_cap = False
                    for chunk in response.iter_bytes():
                        budget = self.max_response_bytes - accumulated
                        if budget <= 0:
                            over_cap = True
                            break
                        if len(chunk) > budget:
                            chunks.append(chunk[:budget])
                            accumulated += budget
                            over_cap = True
                            break
                        chunks.append(chunk)
                        accumulated += len(chunk)
                    if over_cap:
                        # Preserve the accumulated prefix bytes (<= cap) so
                        # the caller can diagnose misbehaving gateways.
                        # Decode lenient (errors='replace') for str form.
                        partial = b"".join(chunks).decode(
                            "utf-8", errors="replace"
                        )
                        # Cap-overflow on a 2xx means "gateway replied with
                        # apparent success but the body we received is not
                        # consumable" — the same rationale as shape-validation
                        # failure. Surface via ResponseValidationError so the
                        # "HTTPError never fires on 2xx" invariant holds
                        # uniformly across every 2xx-body-unusable path.
                        if 200 <= status_code < 300:
                            raise TheVeilResponseValidationError(
                                "response body exceeded max_response_bytes cap of "
                                f"{self.max_response_bytes}",
                                body=partial,
                            )
                        raise TheVeilHttpError(
                            "response body exceeded max_response_bytes cap of "
                            f"{self.max_response_bytes}",
                            status=status_code,
                            body=partial,
                        )
                    raw_bytes = b"".join(chunks)
        except httpx.TimeoutException as exc:
            raise TheVeilTimeoutError(
                f"Request timed out after {timeout_s}s",
                cause=exc,
            ) from exc
        except TheVeilError:
            raise
        except httpx.HTTPError as exc:
            raise TheVeilError("Request failed", cause=exc) from exc

        text = raw_bytes.decode("utf-8", errors="replace")
        parsed_body: Any
        if text:
            try:
                parsed_body = _json.loads(text)
            except ValueError:
                # Non-JSON body — surface the raw text, mirroring TS.
                parsed_body = text
        else:
            parsed_body = text

        if not (200 <= status_code < 300):
            raise TheVeilHttpError(
                f"TheVeil request failed: {status_code} {reason_phrase}",
                status=status_code,
                body=parsed_body,
            )

        return status_code, parsed_body, text


def _parse_proxy_response(status: int, body: Any, raw_text: str) -> ProxyResponse:
    """Discriminate ``messages()`` body into the sync / async union.

    Mirrors the TS SDK's behaviour: ``body["status"] == "processing"`` →
    async; anything else → sync. On malformed bodies, wraps the Pydantic
    ``ValidationError`` in :class:`TheVeilResponseValidationError` — the
    dedicated class for 2xx-wrong-shape responses. The ``status`` kwarg
    is kept for future use (e.g. a follow-up 201/204 semantic branch);
    the current 2xx paths share the same discrimination.

    ``raw_text`` is the pre-parse response text; it's used as a
    fall-back for the error's ``body`` attribute when the parsed body
    is ``None`` (literal JSON ``null`` response), preserving the
    "gateway sent null" signal on the diagnostic surface.
    """

    if isinstance(body, dict) and body.get("status") == "processing":
        try:
            return ProxyAcceptedResponse.model_validate(body)
        except ValidationError as exc:
            # 2xx-but-wrong-shape — dedicated validation error, not HTTP error.
            # The ``isinstance(body, dict)`` guard above means ``body`` is
            # always a dict here, so no raw-text null-fallback is needed.
            raise TheVeilResponseValidationError(
                "Response body failed to deserialize as ProxyAcceptedResponse",
                body=body,
                cause=exc,
            ) from exc
    try:
        return ProxySyncResponse.model_validate(body)
    except ValidationError as exc:
        # Sync branch can be reached with ``body is None`` (literal JSON
        # null) — fall back to the raw pre-parse text so the error's
        # ``.body`` carries the string ``"null"`` rather than Python
        # ``None`` (which would be indistinguishable from "SDK forgot
        # to populate the field").
        effective_body = raw_text if body is None else body
        raise TheVeilResponseValidationError(
            "Response body failed to deserialize as ProxySyncResponse",
            body=effective_body,
            cause=exc,
        ) from exc
