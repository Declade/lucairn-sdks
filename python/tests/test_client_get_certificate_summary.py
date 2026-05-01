"""Lucairn.get_certificate_summary() — HTTP-level tests via respx.

The gateway endpoint is GET /api/v1/veil/certificate/{request_id}/summary
and returns text/html (see
dual-sandbox-architecture/services/gateway/internal/api/veil.go:364-409).
"""

from __future__ import annotations

import httpx
import pytest
import respx

from lucairn import (
    Lucairn,
    LucairnConfig,
    LucairnConfigError,
    LucairnHttpError,
)


VALID_KEY = "dsa_" + "0" * 32
BASE = "https://gateway.lucairn.eu"


def _client() -> Lucairn:
    return Lucairn(LucairnConfig(api_key=VALID_KEY))


class TestGetCertificateSummaryHappyPath:
    @respx.mock
    def test_returns_raw_html_string(self) -> None:
        body = "<html><body><h1>Veil Certificate Summary</h1></body></html>"
        route = respx.get(
            f"{BASE}/api/v1/veil/certificate/req_abc/summary"
        ).mock(
            return_value=httpx.Response(
                200, text=body, headers={"content-type": "text/html"}
            )
        )

        client = _client()
        out = client.get_certificate_summary("req_abc")

        assert route.called
        assert out == body
        # Sanity: API key header was sent.
        sent = route.calls.last.request.headers
        assert sent["x-api-key"] == VALID_KEY

    @respx.mock
    def test_pending_renders_html_at_200(self) -> None:
        # Per gateway source, pending certs render an HTML body at 200,
        # NOT a 202 wrapper. The SDK should pass that HTML straight back.
        pending_html = "<html><body>Certificate pending</body></html>"
        respx.get(
            f"{BASE}/api/v1/veil/certificate/req_pending/summary"
        ).mock(
            return_value=httpx.Response(
                200, text=pending_html, headers={"content-type": "text/html"}
            )
        )

        out = _client().get_certificate_summary("req_pending")
        assert out == pending_html


class TestGetCertificateSummaryErrors:
    def test_request_id_must_be_string(self) -> None:
        with pytest.raises(LucairnConfigError, match="request_id"):
            _client().get_certificate_summary(123)  # type: ignore[arg-type]

    @respx.mock
    def test_non_2xx_raises_http_error(self) -> None:
        respx.get(
            f"{BASE}/api/v1/veil/certificate/req_x/summary"
        ).mock(return_value=httpx.Response(500, text="<html>fail</html>"))

        with pytest.raises(LucairnHttpError) as exc_info:
            _client().get_certificate_summary("req_x")

        assert exc_info.value.status == 500
        # Body remains as the raw text (we never JSON-parse on this endpoint).
        assert exc_info.value.body == "<html>fail</html>"

    @respx.mock
    def test_url_encoding_applied(self) -> None:
        # request_id with slashes / special chars must be percent-encoded
        # so the path doesn't break.
        route = respx.get(
            f"{BASE}/api/v1/veil/certificate/req%2Fweird%3Fid/summary"
        ).mock(return_value=httpx.Response(200, text="<html />"))

        _client().get_certificate_summary("req/weird?id")
        assert route.called
