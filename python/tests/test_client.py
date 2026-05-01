"""Constructor and shared-config validation tests for :class:`Lucairn`.

Port of client.test.ts at the observable level. Python uses seconds (not
milliseconds) for timeout; the validator shape (positive, finite) is
identical.
"""

from __future__ import annotations

import math

import pytest

from lucairn import Lucairn, LucairnConfig, LucairnConfigError


VALID_KEY = "dsa_0123456789abcdef0123456789abcdef"


class TestApiKeyValidation:
    def test_accepts_valid_key(self) -> None:
        client = Lucairn(LucairnConfig(api_key=VALID_KEY))
        assert client is not None

    def test_rejects_wrong_prefix(self) -> None:
        with pytest.raises(LucairnConfigError, match="api_key"):
            Lucairn(LucairnConfig(api_key="bad_" + "0" * 32))

    def test_rejects_uppercase_hex(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn(LucairnConfig(api_key="dsa_" + "A" * 32))

    def test_rejects_wrong_length_too_short(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn(LucairnConfig(api_key="dsa_" + "0" * 31))

    def test_rejects_wrong_length_too_long(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn(LucairnConfig(api_key="dsa_" + "0" * 33))

    def test_rejects_non_string_key(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn(LucairnConfig(api_key=42))  # type: ignore[arg-type]

    def test_rejects_non_config_input(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn({"api_key": VALID_KEY})  # type: ignore[arg-type]


class TestBaseUrl:
    def test_default_base_url(self) -> None:
        client = Lucairn(LucairnConfig(api_key=VALID_KEY))
        assert client.base_url == "https://gateway.lucairn.eu"

    def test_accepts_https_override(self) -> None:
        client = Lucairn(
            LucairnConfig(api_key=VALID_KEY, base_url="https://gateway.example.com")
        )
        assert client.base_url == "https://gateway.example.com"

    def test_accepts_http_for_localhost(self) -> None:
        client = Lucairn(
            LucairnConfig(api_key=VALID_KEY, base_url="http://localhost:8080")
        )
        assert client.base_url == "http://localhost:8080"

    def test_strips_trailing_slashes(self) -> None:
        client = Lucairn(
            LucairnConfig(api_key=VALID_KEY, base_url="https://gateway.example.com///")
        )
        assert client.base_url == "https://gateway.example.com"

    def test_rejects_unknown_scheme(self) -> None:
        with pytest.raises(LucairnConfigError, match="http or https"):
            Lucairn(LucairnConfig(api_key=VALID_KEY, base_url="ftp://example.com"))

    def test_rejects_missing_scheme(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn(LucairnConfig(api_key=VALID_KEY, base_url="example.com"))

    def test_rejects_empty_base_url(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn(LucairnConfig(api_key=VALID_KEY, base_url=""))


class TestTimeout:
    def test_default_timeout(self) -> None:
        client = Lucairn(LucairnConfig(api_key=VALID_KEY))
        assert client.timeout == 30.0

    def test_accepts_positive_int(self) -> None:
        client = Lucairn(LucairnConfig(api_key=VALID_KEY, timeout=5))
        assert client.timeout == 5.0

    def test_accepts_positive_float(self) -> None:
        client = Lucairn(LucairnConfig(api_key=VALID_KEY, timeout=2.5))
        assert client.timeout == 2.5

    def test_rejects_zero(self) -> None:
        with pytest.raises(LucairnConfigError, match="positive"):
            Lucairn(LucairnConfig(api_key=VALID_KEY, timeout=0))

    def test_rejects_negative(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn(LucairnConfig(api_key=VALID_KEY, timeout=-1))

    def test_rejects_nan(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn(LucairnConfig(api_key=VALID_KEY, timeout=math.nan))

    def test_rejects_positive_infinity(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn(LucairnConfig(api_key=VALID_KEY, timeout=math.inf))

    def test_rejects_negative_infinity(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn(LucairnConfig(api_key=VALID_KEY, timeout=-math.inf))

    def test_rejects_bool(self) -> None:
        # bool subclasses int; explicitly reject so True/False never become a
        # timeout of 1s / 0s.
        with pytest.raises(LucairnConfigError):
            Lucairn(LucairnConfig(api_key=VALID_KEY, timeout=True))  # type: ignore[arg-type]

    def test_rejects_non_numeric(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn(LucairnConfig(api_key=VALID_KEY, timeout="10"))  # type: ignore[arg-type]


class TestHTTPBaseURLGuard:
    """http:// is rejected for non-loopback hosts — API-key exfiltration guard."""

    @pytest.mark.parametrize(
        "host",
        ["localhost", "127.0.0.1", "::1", "myservice.local"],
    )
    def test_accepts_http_for_loopback_and_mdns(self, host: str) -> None:
        # Handle IPv6 bracket-wrapping for ::1
        if host == "::1":
            url = f"http://[{host}]:8080"
        else:
            url = f"http://{host}:8080"
        client = Lucairn(LucairnConfig(api_key=VALID_KEY, base_url=url))
        assert client.base_url == url.rstrip("/")

    def test_rejects_http_on_public_host(self) -> None:
        with pytest.raises(LucairnConfigError, match="https://"):
            Lucairn(
                LucairnConfig(
                    api_key=VALID_KEY, base_url="http://gateway.example.com"
                )
            )

    def test_rejects_http_on_ip_outside_loopback(self) -> None:
        with pytest.raises(LucairnConfigError, match="https://"):
            Lucairn(
                LucairnConfig(api_key=VALID_KEY, base_url="http://10.0.0.1")
            )

    def test_accepts_https_everywhere(self) -> None:
        for url in ("https://gateway.lucairn.eu", "https://10.0.0.1", "https://example.com"):
            client = Lucairn(LucairnConfig(api_key=VALID_KEY, base_url=url))
            assert client.base_url == url


class TestMaxResponseBytes:
    def test_default_is_10mib(self) -> None:
        client = Lucairn(LucairnConfig(api_key=VALID_KEY))
        assert client.max_response_bytes == 10 * 1024 * 1024

    def test_accepts_positive_int(self) -> None:
        client = Lucairn(
            LucairnConfig(api_key=VALID_KEY, max_response_bytes=1024)
        )
        assert client.max_response_bytes == 1024

    def test_rejects_zero(self) -> None:
        with pytest.raises(LucairnConfigError, match="max_response_bytes"):
            Lucairn(LucairnConfig(api_key=VALID_KEY, max_response_bytes=0))

    def test_rejects_negative(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn(LucairnConfig(api_key=VALID_KEY, max_response_bytes=-1))

    def test_rejects_bool(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn(
                LucairnConfig(api_key=VALID_KEY, max_response_bytes=True)  # type: ignore[arg-type]
            )

    def test_rejects_non_int(self) -> None:
        with pytest.raises(LucairnConfigError):
            Lucairn(
                LucairnConfig(api_key=VALID_KEY, max_response_bytes=1024.0)  # type: ignore[arg-type]
            )


class TestApiKeyIsPrivate:
    def test_api_key_not_on_public_attrs(self) -> None:
        client = Lucairn(LucairnConfig(api_key=VALID_KEY))
        assert not hasattr(client, "api_key")

    def test_api_key_not_in_repr(self) -> None:
        client = Lucairn(LucairnConfig(api_key=VALID_KEY))
        assert VALID_KEY not in repr(client)
