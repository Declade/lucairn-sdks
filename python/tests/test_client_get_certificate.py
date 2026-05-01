"""Lucairn.get_certificate() — HTTP-level tests via respx.

Port of client.getCertificate.test.ts at the observable level. Language
divergences:

* No caller-initiated abort/cancel — v1 sync client has timeout only
  (locked decision 2026-04-20 §3). Caller-abort test omitted; timeout
  test retained.

* Malformed 200 body: TS returns raw text typed as ``VeilCertificate``
  (thin-transport, passes through). Python calls
  ``VeilCertificate.model_validate(body)`` at deserialize time and
  wraps ``ValidationError`` as :class:`LucairnResponseValidationError`
  — a dedicated error class distinct from :class:`LucairnHttpError`
  (which is reserved for gateway non-2xx). Both languages surface a
  typed error to the caller; Python fails at fetch, TS at
  ``verify_certificate``.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
import respx

from lucairn import (
    MessagesOptions,
    Lucairn,
    LucairnConfig,
    LucairnConfigError,
    LucairnError,
    LucairnHttpError,
    LucairnResponseValidationError,
    LucairnTimeoutError,
)

VALID_KEY = "dsa_0123456789abcdef0123456789abcdef"
BASE = "https://gateway.lucairn.eu"
CERT_PATH_PREFIX = "/api/v1/veil/certificate/"


def _client() -> Lucairn:
    return Lucairn(LucairnConfig(api_key=VALID_KEY))


class TestHappyPath:
    @respx.mock
    def test_returns_cert_body_deep_equal(
        self, cert_valid_anchored: dict[str, Any]
    ) -> None:
        request_id = cert_valid_anchored["request_id"]
        route = respx.get(f"{BASE}{CERT_PATH_PREFIX}{request_id}").respond(
            200, json=cert_valid_anchored
        )
        client = _client()
        cert = client.get_certificate(request_id)
        assert route.called
        # Deep-compare model fields against the fixture source; fields the
        # Pydantic model declares with coercion are structurally equal.
        assert cert.certificate_id == cert_valid_anchored["certificate_id"]
        assert cert.request_id == cert_valid_anchored["request_id"]
        assert cert.protocol_version == 2
        assert cert.witness_key_id == "witness_v1"
        assert cert.witness_signature == cert_valid_anchored["witness_signature"]

    @respx.mock
    def test_sends_x_api_key_header_and_scoped_path(
        self, cert_valid_anchored: dict[str, Any]
    ) -> None:
        request_id = "req_test_0000000000000001"
        route = respx.get(f"{BASE}{CERT_PATH_PREFIX}{request_id}").respond(
            200, json=cert_valid_anchored
        )
        client = _client()
        client.get_certificate(request_id)
        assert route.called
        sent: httpx.Request = route.calls.last.request
        assert sent.url.path == f"{CERT_PATH_PREFIX}{request_id}"
        assert sent.headers.get("x-api-key") == VALID_KEY


class TestPending202:
    @respx.mock
    def test_raises_http_error_with_status_202_and_wrapper_body(self) -> None:
        pending_body = {
            "status": "pending",
            "request_id": "req_pending_0001",
            "message": "Veil certificate is not ready yet.",
            "retry_after_seconds": 30,
        }
        respx.get(f"{BASE}{CERT_PATH_PREFIX}req_pending_0001").respond(
            202, json=pending_body
        )
        client = _client()
        with pytest.raises(LucairnHttpError) as exc_info:
            client.get_certificate("req_pending_0001")
        err = exc_info.value
        assert err.status == 202
        assert err.body == pending_body
        assert err.body["status"] == "pending"
        assert err.body["retry_after_seconds"] == 30


class TestHttpErrorMapping:
    """Each gateway error envelope maps to LucairnHttpError preserving status + body."""

    @pytest.mark.parametrize(
        ("status", "label"),
        [
            (401, "missing_api_key"),
            (401, "invalid_api_key"),
            (403, "tier_insufficient"),
            (404, "veil_not_configured"),
            (502, "upstream_error"),
        ],
    )
    @respx.mock
    def test_maps_status_and_code(self, status: int, label: str) -> None:
        body: dict[str, Any] = {
            "error": {"code": label, "message": f"test {label}"}
        }
        respx.get(f"{BASE}{CERT_PATH_PREFIX}req_err_0001").respond(
            status_code=status, json=body
        )
        client = _client()
        with pytest.raises(LucairnHttpError) as exc_info:
            client.get_certificate("req_err_0001")
        err = exc_info.value
        assert isinstance(err, LucairnError)
        assert err.status == status
        assert err.body == body
        assert err.body["error"]["code"] == label

    @respx.mock
    def test_503_veil_unavailable_carries_retry_after_seconds_in_body(self) -> None:
        body: dict[str, Any] = {
            "error": {
                "code": "veil_unavailable",
                "message": "Veil Witness is temporarily unavailable.",
                "retry_after_seconds": 30,
            }
        }
        respx.get(f"{BASE}{CERT_PATH_PREFIX}req_unavailable_0001").respond(
            status_code=503, json=body
        )
        client = _client()
        with pytest.raises(LucairnHttpError) as exc_info:
            client.get_certificate("req_unavailable_0001")
        err = exc_info.value
        assert err.status == 503
        assert err.body["error"]["retry_after_seconds"] == 30


class TestTransportErrors:
    @respx.mock
    def test_network_error_wraps_to_the_veil_error_not_http_error(self) -> None:
        respx.get(f"{BASE}{CERT_PATH_PREFIX}req_network_0001").mock(
            side_effect=httpx.ConnectError("boom")
        )
        client = _client()
        with pytest.raises(LucairnError) as exc_info:
            client.get_certificate("req_network_0001")
        err = exc_info.value
        assert not isinstance(err, LucairnHttpError)


class TestTimeout:
    @respx.mock
    def test_timeout_raises_the_veil_timeout_error(self) -> None:
        respx.get(f"{BASE}{CERT_PATH_PREFIX}req_slow_0001").mock(
            side_effect=httpx.TimeoutException("simulated")
        )
        client = _client()
        with pytest.raises(LucairnTimeoutError, match=r"\d"):
            client.get_certificate(
                "req_slow_0001", options=MessagesOptions(timeout=0.05)
            )

    def test_rejects_invalid_per_call_timeout(self) -> None:
        client = _client()
        with pytest.raises(LucairnConfigError, match="options.timeout"):
            client.get_certificate(
                "req_x", options=MessagesOptions(timeout=-1)
            )


class TestPathEncoding:
    @respx.mock
    def test_percent_encodes_reserved_chars(
        self, cert_valid_anchored: dict[str, Any]
    ) -> None:
        # The encoded path must match what respx sees: slash → %2F,
        # space → %20, question mark → %3F.
        encoded_path = f"{CERT_PATH_PREFIX}req%2Fweird%20id%3F"
        route = respx.get(f"{BASE}{encoded_path}").respond(
            200, json=cert_valid_anchored
        )
        client = _client()
        client.get_certificate("req/weird id?")
        assert route.called
        sent: httpx.Request = route.calls.last.request
        assert sent.url.raw_path.decode() == encoded_path
        assert "req/weird id?" not in str(sent.url)

    def test_rejects_non_string_request_id(self) -> None:
        client = _client()
        with pytest.raises(LucairnConfigError, match="request_id"):
            client.get_certificate(12345)  # type: ignore[arg-type]


class TestLiteralNullBody:
    @respx.mock
    def test_literal_null_body_preserves_null_signal(self) -> None:
        # A 2xx with literal JSON null parses to Python None, fails
        # Pydantic validation, and must surface as
        # LucairnResponseValidationError with body = "null" (the raw
        # pre-parse text) — NOT None. Callers can distinguish "gateway
        # sent null" from "SDK forgot to populate .body."
        respx.get(f"{BASE}{CERT_PATH_PREFIX}req_null").respond(
            200, text="null", headers={"content-type": "application/json"}
        )
        client = _client()
        with pytest.raises(LucairnResponseValidationError) as exc_info:
            client.get_certificate("req_null")
        err = exc_info.value
        # body is the raw pre-parse text, not parsed None.
        assert err.body == "null", f"body = {err.body!r}"
        assert err.body is not None


class TestMalformed200:
    """Observed behaviour: non-JSON / wrong-shape 200 surfaces as
    :class:`LucairnResponseValidationError` — distinct from
    :class:`LucairnHttpError` so callers can branch cleanly on
    "transport failed" vs "body doesn't fit declared type".
    """

    @respx.mock
    def test_non_json_200_body_raises_response_validation_error(self) -> None:
        respx.get(f"{BASE}{CERT_PATH_PREFIX}req_malformed_0001").respond(
            200, text="not json at all", headers={"content-type": "text/plain"}
        )
        client = _client()
        with pytest.raises(LucairnResponseValidationError) as exc_info:
            client.get_certificate("req_malformed_0001")
        err = exc_info.value
        # The body is the raw text since it failed JSON parsing upstream.
        assert err.body == "not json at all"
        # And NOT an HTTP error — that would lie about the transport layer.
        assert not isinstance(err, LucairnHttpError)

    @respx.mock
    def test_missing_required_fields_200_raises_response_validation_error(
        self,
    ) -> None:
        # A 200 with JSON but missing `certificate_id` — Pydantic raises
        # ValidationError; the client wraps as LucairnResponseValidationError
        # and preserves the Pydantic error as __cause__ for field-level
        # inspection by callers.
        from pydantic import ValidationError

        respx.get(f"{BASE}{CERT_PATH_PREFIX}req_partial_0001").respond(
            200, json={"not_a_cert": True}
        )
        client = _client()
        with pytest.raises(LucairnResponseValidationError) as exc_info:
            client.get_certificate("req_partial_0001")
        err = exc_info.value
        assert isinstance(err.body, dict)
        assert err.body == {"not_a_cert": True}
        # Callers can introspect the Pydantic validation details.
        assert isinstance(err.__cause__, ValidationError)
        # Still satisfies the base SDK error class — callers doing
        # ``except LucairnError`` still catch it.
        assert isinstance(err, LucairnError)

    @respx.mock
    def test_non_2xx_still_raises_http_error_not_response_validation_error(
        self,
    ) -> None:
        # Invariant: non-2xx keeps LucairnHttpError. The new class must NEVER
        # fire for a transport-level failure.
        respx.get(f"{BASE}{CERT_PATH_PREFIX}req_gone").respond(
            404, json={"error": {"code": "veil_not_configured"}}
        )
        client = _client()
        with pytest.raises(LucairnHttpError) as exc_info:
            client.get_certificate("req_gone")
        assert exc_info.value.status == 404
        assert not isinstance(exc_info.value, LucairnResponseValidationError)


class TestMaxResponseBytesEnforcement:
    @respx.mock
    def test_2xx_over_cap_raises_response_validation_error(self) -> None:
        # Deliberately ship 1 KB when the cap is 256 bytes. On a 2xx status
        # the over-cap path raises LucairnResponseValidationError — the
        # body was not consumable, which is semantically the same class of
        # 2xx-body-unusable failure as a wrong-shape body. *HTTPError*
        # stays reserved for non-2xx transport failures.
        respx.get(f"{BASE}{CERT_PATH_PREFIX}req_big").respond(
            200,
            text="PREFIX_MARKER_" + "x" * 1024,
            headers={"content-type": "text/plain"},
        )
        client = Lucairn(
            LucairnConfig(api_key=VALID_KEY, max_response_bytes=256)
        )
        with pytest.raises(
            LucairnResponseValidationError, match="max_response_bytes"
        ) as exc_info:
            client.get_certificate("req_big")
        # Invariant: must NOT also be LucairnHttpError.
        assert not isinstance(exc_info.value, LucairnHttpError)
        # Body preservation: the accumulated prefix bytes must be on the
        # error so callers can diagnose misbehaving gateways. We check
        # both non-emptiness and the marker is present.
        assert exc_info.value.body, "body should carry the accumulated prefix"
        assert isinstance(exc_info.value.body, str)
        assert "PREFIX_MARKER_" in exc_info.value.body

    @respx.mock
    def test_non_2xx_over_cap_still_raises_http_error(self) -> None:
        # Cap-overflow on a non-2xx keeps *HTTPError* — the caller saw a
        # transport error AND an oversized body; the transport error is
        # the dominant signal. Body preservation applies to this path too.
        respx.get(f"{BASE}{CERT_PATH_PREFIX}req_big_err").respond(
            502,
            text="ERROR_MARKER_" + "x" * 1024,
            headers={"content-type": "text/plain"},
        )
        client = Lucairn(
            LucairnConfig(api_key=VALID_KEY, max_response_bytes=256)
        )
        with pytest.raises(LucairnHttpError, match="max_response_bytes") as exc_info:
            client.get_certificate("req_big_err")
        assert exc_info.value.status == 502
        assert exc_info.value.body, "body should carry the accumulated prefix"
        assert isinstance(exc_info.value.body, str)
        assert "ERROR_MARKER_" in exc_info.value.body

    @respx.mock
    def test_response_at_cap_is_accepted(
        self, cert_valid_anchored: dict[str, Any]
    ) -> None:
        # A normal-sized cert fits easily under the 1 MiB cap we set.
        respx.get(f"{BASE}{CERT_PATH_PREFIX}req_ok").respond(
            200, json=cert_valid_anchored
        )
        client = Lucairn(
            LucairnConfig(api_key=VALID_KEY, max_response_bytes=1024 * 1024)
        )
        cert = client.get_certificate("req_ok")
        assert cert.certificate_id == cert_valid_anchored["certificate_id"]


class TestPerCallHeaderMerge:
    @respx.mock
    def test_caller_headers_merged_sdk_owned_keys_win(
        self, cert_valid_anchored: dict[str, Any]
    ) -> None:
        route = respx.get(f"{BASE}{CERT_PATH_PREFIX}req_h").respond(
            200, json=cert_valid_anchored
        )
        client = _client()
        client.get_certificate(
            "req_h",
            options=MessagesOptions(
                headers={
                    "x-correlation-id": "corr_abc",
                    # Caller attempts to override x-api-key and content-type;
                    # SDK-owned keys must win.
                    "x-api-key": "dsa_" + "f" * 32,
                    "content-type": "text/plain",
                }
            ),
        )
        assert route.called
        sent: httpx.Request = route.calls.last.request
        assert sent.headers.get("x-correlation-id") == "corr_abc"
        assert sent.headers.get("x-api-key") == VALID_KEY
        assert sent.headers.get("content-type") == "application/json"
