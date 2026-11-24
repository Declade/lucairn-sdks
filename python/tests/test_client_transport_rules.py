"""Transport rules for key-carrying requests (security fix stream T-1474,
slice F16; level-2 entry 11 and low 12):

- the client never follows a redirect, so the api_key is never sent to the
  address a Location header names;
- plain ``http://`` base addresses are refused except for this machine.

Synthetic key, two local stand-in servers only.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from lucairn import Lucairn, LucairnConfig
from lucairn.errors import LucairnConfigError, LucairnHttpError

SYNTHETIC_KEY = "dsa_" + "0" * 32


def _serve(handler_cls: type[BaseHTTPRequestHandler]) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_redirect_to_another_local_port_is_error_and_key_not_sent() -> None:
    second_saw: list[dict[str, str]] = []

    class Second(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            second_saw.append(dict(self.headers))
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *args: object) -> None:
            pass

    second = _serve(Second)
    target = f"http://127.0.0.1:{second.server_address[1]}/v1/x"

    class First(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(307)
            self.send_header("location", target)
            self.send_header("content-length", "0")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    first = _serve(First)
    try:
        client = Lucairn(
            LucairnConfig(api_key=SYNTHETIC_KEY, base_url=f"http://127.0.0.1:{first.server_address[1]}")
        )
        with pytest.raises(LucairnHttpError) as exc:
            client.get_certificate("req_f16_redirect")
        assert exc.value.status == 307
        assert second_saw == []
    finally:
        first.shutdown()
        second.shutdown()


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost:8080",
        "http://LOCALHOST:8080",
        "HTTP://127.0.0.1:8080",
        "http://127.10.20.30",
        "http://[::1]:8080",
        "https://gateway.example.com",
    ],
)
def test_loopback_http_and_https_accepted(url: str) -> None:
    Lucairn(LucairnConfig(api_key=SYNTHETIC_KEY, base_url=url))


@pytest.mark.parametrize(
    "url",
    [
        "http://gateway.example.com",
        "HTTP://gateway.example.com",
        "http://localhost.evil.example",
        "http://localhost@evil.example",
        "http://127.0.0.1@evil.example",
        "http://127.0.0.1.evil.example",
        "http://evil.example#@localhost",
        "http://128.0.0.1",
        "http://myservice.local",
        "http://[::ffff:127.0.0.1]",
    ],
)
def test_plain_http_refused_off_this_machine(url: str) -> None:
    with pytest.raises(LucairnConfigError):
        Lucairn(LucairnConfig(api_key=SYNTHETIC_KEY, base_url=url))
