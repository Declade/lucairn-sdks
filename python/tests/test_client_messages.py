"""Lucairn.messages() — HTTP-level tests via respx.

Port of client.messages.test.ts at the observable level. Python uses
seconds for timeout (not ms) and has no caller-abort surface (locked
decision 2026-04-20 §3).
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from lucairn import (
    MessagesOptions,
    ProxyAcceptedResponse,
    ProxyMessagesRequest,
    ProxySyncResponse,
    Lucairn,
    LucairnConfig,
    LucairnConfigError,
    LucairnHttpError,
    LucairnResponseValidationError,
    LucairnTimeoutError,
)

VALID_KEY = "dsa_0123456789abcdef0123456789abcdef"
BASE = "https://gateway.dsaveil.io"
MESSAGES_URL = f"{BASE}/api/v1/proxy/messages"


def _client() -> Lucairn:
    return Lucairn(LucairnConfig(api_key=VALID_KEY))


def _params() -> ProxyMessagesRequest:
    return ProxyMessagesRequest(
        prompt_template="hello {customer}",
        context={"customer": "Ada"},
        model="claude-opus-4-7",
        max_tokens=256,
    )


class TestHappyPathSync:
    @respx.mock
    def test_returns_proxy_sync_response_on_completed_200(self) -> None:
        body: dict[str, Any] = {
            "status": "JOB_STATUS_COMPLETED",
            "model_used": "claude-opus-4-7",
            "latency_ms": 1234,
            "result": {"content": [{"type": "text", "text": "Hello, Ada."}]},
        }
        route = respx.post(MESSAGES_URL).respond(200, json=body)
        client = _client()
        result = client.messages(_params())
        assert route.called
        assert isinstance(result, ProxySyncResponse)
        assert result.status == "JOB_STATUS_COMPLETED"
        assert result.model_used == "claude-opus-4-7"
        assert result.latency_ms == 1234
        assert result.result == body["result"]

    @respx.mock
    def test_returns_proxy_sync_response_on_failed_200(self) -> None:
        body: dict[str, Any] = {
            "status": "JOB_STATUS_FAILED",
            "model_used": "claude-opus-4-7",
            "latency_ms": 42,
            "error_message": "upstream model timeout",
        }
        respx.post(MESSAGES_URL).respond(200, json=body)
        result = _client().messages(_params())
        assert isinstance(result, ProxySyncResponse)
        assert result.status == "JOB_STATUS_FAILED"
        assert result.error_message == "upstream model timeout"

    @respx.mock
    def test_sends_api_key_and_content_type_headers(self) -> None:
        body: dict[str, Any] = {
            "status": "JOB_STATUS_COMPLETED",
            "model_used": "x",
            "latency_ms": 1,
        }
        route = respx.post(MESSAGES_URL).respond(200, json=body)
        _client().messages(_params())
        sent: httpx.Request = route.calls.last.request
        assert sent.headers.get("x-api-key") == VALID_KEY
        assert sent.headers.get("content-type") == "application/json"


class TestAsync202Discriminator:
    @respx.mock
    def test_returns_proxy_accepted_response_when_body_status_is_processing(
        self,
    ) -> None:
        body: dict[str, Any] = {
            "status": "processing",
            "job_id": "job_abc",
            "request_id": "req_xyz",
            "status_url": f"{BASE}/api/v1/proxy/messages/job_abc",
            "veil": {
                "status": "pending",
                "certificate_url": f"{BASE}/api/v1/veil/certificate/req_xyz",
                "summary_url": f"{BASE}/api/v1/veil/certificate/req_xyz/summary",
            },
        }
        respx.post(MESSAGES_URL).respond(202, json=body)
        result = _client().messages(_params())
        assert isinstance(result, ProxyAcceptedResponse)
        assert result.status == "processing"
        assert result.job_id == "job_abc"
        assert result.request_id == "req_xyz"
        assert result.veil is not None
        assert result.veil.status == "pending"


class TestErrorMapping:
    @respx.mock
    def test_401_invalid_api_key_raises_http_error(self) -> None:
        body: dict[str, Any] = {
            "error": {"code": "invalid_api_key", "message": "no"}
        }
        respx.post(MESSAGES_URL).respond(401, json=body)
        with pytest.raises(LucairnHttpError) as exc_info:
            _client().messages(_params())
        assert exc_info.value.status == 401
        assert exc_info.value.body == body


class TestPerCallOptions:
    @respx.mock
    def test_per_call_headers_merged_with_sdk_keys_winning(self) -> None:
        body: dict[str, Any] = {
            "status": "JOB_STATUS_COMPLETED",
            "model_used": "x",
            "latency_ms": 1,
        }
        route = respx.post(MESSAGES_URL).respond(200, json=body)
        _client().messages(
            _params(),
            options=MessagesOptions(
                headers={
                    "x-correlation-id": "corr_abc",
                    # Caller override attempt — SDK-owned must win.
                    "x-api-key": "dsa_" + "f" * 32,
                }
            ),
        )
        sent = route.calls.last.request
        assert sent.headers.get("x-correlation-id") == "corr_abc"
        assert sent.headers.get("x-api-key") == VALID_KEY

    @respx.mock
    def test_per_call_timeout_overrides_client_default(self) -> None:
        respx.post(MESSAGES_URL).mock(
            side_effect=httpx.TimeoutException("simulated")
        )
        with pytest.raises(LucairnTimeoutError, match=r"\d"):
            _client().messages(_params(), options=MessagesOptions(timeout=0.01))


class TestValidation:
    def test_rejects_stream_true(self) -> None:
        params = ProxyMessagesRequest(
            prompt_template="x", context={}, stream=True
        )
        with pytest.raises(LucairnConfigError, match="stream"):
            _client().messages(params)

    def test_rejects_nan_max_tokens(self) -> None:
        import math
        # ProxyMessagesRequest validates via Pydantic, which rejects NaN for
        # int fields with a validation error; the client wraps config errors.
        # Here we bypass by constructing a dict (simulating untyped input).
        with pytest.raises(LucairnConfigError):
            _client().messages({"prompt_template": "x", "context": {}, "max_tokens": math.nan})

    def test_rejects_non_request_params(self) -> None:
        with pytest.raises(LucairnConfigError):
            _client().messages("garbage")  # type: ignore[arg-type]

    @respx.mock
    def test_accepts_dict_params(self) -> None:
        body: dict[str, Any] = {
            "status": "JOB_STATUS_COMPLETED",
            "model_used": "x",
            "latency_ms": 1,
        }
        respx.post(MESSAGES_URL).respond(200, json=body)
        result = _client().messages(
            {"prompt_template": "hello", "context": {"k": "v"}}
        )
        assert isinstance(result, ProxySyncResponse)


class TestLatencyMsLeniency:
    """DRIFT-001 alignment: Python now matches Go's lenient `latency_ms`
    treatment. A gateway that omits the field, emits 0 on sub-ms paths,
    or explicitly sends 0 must return a valid ProxySyncResponse — not
    raise LucairnResponseValidationError.
    """

    @respx.mock
    def test_omitted_latency_ms_parses_with_zero_default(self) -> None:
        # latency_ms absent from the body entirely; Pydantic applies the
        # field default of 0 rather than rejecting.
        body: dict[str, Any] = {
            "status": "JOB_STATUS_COMPLETED",
            "model_used": "claude-opus-4-7",
            # no latency_ms
        }
        respx.post(MESSAGES_URL).respond(200, json=body)
        resp = _client().messages(_params())
        assert isinstance(resp, ProxySyncResponse)
        assert resp.latency_ms == 0

    @respx.mock
    def test_explicit_zero_latency_ms_parses(self) -> None:
        body: dict[str, Any] = {
            "status": "JOB_STATUS_COMPLETED",
            "model_used": "claude-opus-4-7",
            "latency_ms": 0,
        }
        respx.post(MESSAGES_URL).respond(200, json=body)
        resp = _client().messages(_params())
        assert isinstance(resp, ProxySyncResponse)
        assert resp.latency_ms == 0


class TestLiteralNullBody:
    @respx.mock
    def test_literal_null_body_preserves_null_signal(self) -> None:
        # Mirrors TestLiteralNullBody in test_client_get_certificate.py —
        # the messages() path must behave identically for a literal null
        # 2xx response.
        respx.post(MESSAGES_URL).respond(
            200, text="null", headers={"content-type": "application/json"}
        )
        with pytest.raises(LucairnResponseValidationError) as exc_info:
            _client().messages(_params())
        err = exc_info.value
        assert err.body == "null", f"body = {err.body!r}"
        assert err.body is not None


class TestMalformed200:
    @respx.mock
    def test_missing_required_sync_fields_raises_response_validation_error(
        self,
    ) -> None:
        # A 200 with a body that's not processing, not a valid sync response
        # either (missing model_used, latency_ms) — wraps as
        # LucairnResponseValidationError (NOT LucairnHttpError, which is
        # reserved for transport-level non-2xx).
        respx.post(MESSAGES_URL).respond(
            200, json={"status": "JOB_STATUS_COMPLETED"}
        )
        with pytest.raises(LucairnResponseValidationError) as exc_info:
            _client().messages(_params())
        err = exc_info.value
        assert err.body == {"status": "JOB_STATUS_COMPLETED"}
        assert not isinstance(err, LucairnHttpError)

    @respx.mock
    def test_missing_required_async_fields_raises_response_validation_error(
        self,
    ) -> None:
        # body["status"] == "processing" triggers the async branch; if its
        # required fields (job_id, status_url, request_id) are missing,
        # Pydantic rejects and the client wraps as
        # LucairnResponseValidationError.
        respx.post(MESSAGES_URL).respond(
            202, json={"status": "processing"}
        )
        with pytest.raises(LucairnResponseValidationError) as exc_info:
            _client().messages(_params())
        err = exc_info.value
        assert err.body == {"status": "processing"}
        assert not isinstance(err, LucairnHttpError)

    @respx.mock
    def test_non_2xx_still_raises_http_error(self) -> None:
        # Invariant: non-2xx keeps LucairnHttpError. ResponseValidationError
        # must NEVER fire for transport-level failure.
        respx.post(MESSAGES_URL).respond(
            500, json={"error": {"code": "upstream_error"}}
        )
        with pytest.raises(LucairnHttpError) as exc_info:
            _client().messages(_params())
        assert exc_info.value.status == 500
        assert not isinstance(exc_info.value, LucairnResponseValidationError)
