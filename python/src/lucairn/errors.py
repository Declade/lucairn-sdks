from __future__ import annotations

from typing import Any, Literal

VerifyCertificateFailureReason = Literal[
    "malformed",
    "unsupported_protocol_version",
    "witness_mismatch",
    "witness_signature_missing",
    "invalid_signature",
]


class TheVeilError(Exception):
    """Base class for all TheVeil SDK errors.

    Callers can catch this to handle every SDK-raised error uniformly. More
    specific subclasses carry additional context (status codes, failure
    reasons) — see their docstrings.
    """

    def __init__(self, message: str, *, cause: BaseException | None = None) -> None:
        super().__init__(message)
        if cause is not None:
            self.__cause__ = cause


class TheVeilConfigError(TheVeilError):
    """Raised when a constructor / per-call option is invalid.

    Examples: malformed apiKey, non-https baseUrl in production, non-finite
    timeout. These are caller-correctable.
    """


class TheVeilHttpError(TheVeilError):
    """Raised when the gateway returns a non-2xx response, or a 202 pending
    wrapper on get_certificate.

    The ``status`` attribute is the real HTTP status. The ``body`` attribute
    is the parsed JSON body (dict or list) when the response parses as JSON,
    otherwise the raw response text. Callers branch on ``err.status`` to
    distinguish auth errors (401/403), transient errors (502/503), or a
    pending certificate (202 with ``body["status"] == "pending"``).
    """

    status: int
    body: Any

    def __init__(
        self,
        message: str,
        status: int,
        body: Any,
        *,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message, cause=cause)
        self.status = status
        self.body = body


class TheVeilTimeoutError(TheVeilError):
    """Raised when a request exceeds its per-call or client-default timeout.

    Distinct from a caller-initiated cancel — this SDK's v1 sync client has
    no cancel surface (timeout is the only way to bound a request). Cancel
    support arrives with the async client in a later arc.
    """


class TheVeilResponseValidationError(TheVeilError):
    """Raised when a 2xx gateway response deserializes into a shape that
    doesn't fit the SDK's declared response type (either JSON that fails
    Pydantic validation, or a non-JSON body on a 2xx status).

    Distinct from :class:`TheVeilHttpError`, which is reserved for gateway
    non-2xx responses and the 202 pending wrapper on ``get_certificate``.
    A response-validation error means "the gateway replied with apparent
    success, but the body we got doesn't look like the declared type" —
    typically a gateway bug or version skew, not a transport failure.

    Attributes:
        body: Raw deserialized body — a dict / list / primitive when the
            response parsed as JSON, or the raw text otherwise.

    The ``__cause__`` attribute preserves the underlying Pydantic
    :class:`pydantic.ValidationError` or :class:`ValueError` so callers
    can inspect field-level detail if they need to.

    Matches the shape of ``openai.APIResponseValidationError`` and
    ``anthropic.APIResponseValidationError`` — the nearest-sibling typed
    Python SDK precedent.
    """

    body: Any

    def __init__(
        self,
        message: str,
        *,
        body: Any,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message, cause=cause)
        self.body = body


class TheVeilCertificateError(TheVeilError):
    """Raised by verify_certificate when verification fails.

    ``reason`` names the specific failure mode. ``certificate_id`` is lifted
    from ``cert["certificate_id"]`` for error-context logging.

    SECURITY NOTE: on all failure paths the ``certificate_id`` value is
    UNVERIFIED — the witness signature has not yet been (or failed to)
    verify by the time this ID is attached. An attacker or malformed cert
    can set any string here. Consumers logging this field should treat it
    as untrusted input (escape / truncate / bound length). Only on the
    success return path (``VerifyCertificateResult.certificate_id``) is
    this value covered by the witness signature.
    """

    reason: VerifyCertificateFailureReason
    certificate_id: str | None

    def __init__(
        self,
        message: str,
        *,
        reason: VerifyCertificateFailureReason,
        certificate_id: str | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message, cause=cause)
        self.reason = reason
        self.certificate_id = certificate_id
