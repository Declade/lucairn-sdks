"""Error class identity + attribute tests."""

from __future__ import annotations

import pytest

from lucairn import (
    LucairnCertificateError,
    LucairnConfigError,
    LucairnError,
    LucairnHttpError,
    LucairnResponseValidationError,
    LucairnTimeoutError,
)


class TestErrorHierarchy:
    def test_base_is_exception(self) -> None:
        err = LucairnError("x")
        assert isinstance(err, Exception)

    def test_config_inherits_base(self) -> None:
        err = LucairnConfigError("x")
        assert isinstance(err, LucairnError)
        assert isinstance(err, Exception)

    def test_http_inherits_base(self) -> None:
        err = LucairnHttpError("x", status=500, body=None)
        assert isinstance(err, LucairnError)

    def test_timeout_inherits_base(self) -> None:
        err = LucairnTimeoutError("x")
        assert isinstance(err, LucairnError)

    def test_certificate_inherits_base(self) -> None:
        err = LucairnCertificateError("x", reason="malformed")
        assert isinstance(err, LucairnError)

    def test_response_validation_inherits_base(self) -> None:
        err = LucairnResponseValidationError("x", body={})
        assert isinstance(err, LucairnError)

    def test_response_validation_is_not_an_http_error(self) -> None:
        # Catching LucairnHttpError must NOT catch a response-validation
        # failure — they are distinct surfaces (transport vs. body shape).
        err = LucairnResponseValidationError("x", body={})
        assert not isinstance(err, LucairnHttpError)


class TestLucairnHttpError:
    def test_status_and_body_accessible(self) -> None:
        err = LucairnHttpError("bad", status=401, body={"error": "nope"})
        assert err.status == 401
        assert err.body == {"error": "nope"}

    def test_message_on_str(self) -> None:
        err = LucairnHttpError("bad", status=500, body=None)
        assert str(err) == "bad"

    def test_cause_attached(self) -> None:
        inner = ValueError("inner")
        err = LucairnHttpError("bad", status=500, body=None, cause=inner)
        assert err.__cause__ is inner


class TestLucairnCertificateError:
    def test_reason_and_certificate_id(self) -> None:
        err = LucairnCertificateError(
            "nope",
            reason="invalid_signature",
            certificate_id="veil_xyz",
        )
        assert err.reason == "invalid_signature"
        assert err.certificate_id == "veil_xyz"

    def test_certificate_id_defaults_none(self) -> None:
        err = LucairnCertificateError("nope", reason="malformed")
        assert err.certificate_id is None

    def test_cause_preserved(self) -> None:
        inner = TypeError("boom")
        err = LucairnCertificateError(
            "wrap", reason="invalid_signature", cause=inner
        )
        assert err.__cause__ is inner


class TestLucairnConfigError:
    def test_accepts_single_argument(self) -> None:
        err = LucairnConfigError("config bad")
        assert str(err) == "config bad"


class TestLucairnTimeoutError:
    def test_accepts_single_argument(self) -> None:
        err = LucairnTimeoutError("slow")
        assert str(err) == "slow"


class TestLucairnResponseValidationError:
    def test_body_accessible(self) -> None:
        err = LucairnResponseValidationError(
            "bad shape", body={"unexpected": True}
        )
        assert err.body == {"unexpected": True}

    def test_cause_preserved(self) -> None:
        inner = ValueError("not json")
        err = LucairnResponseValidationError("bad", body="raw text", cause=inner)
        assert err.__cause__ is inner

    def test_body_may_be_raw_text(self) -> None:
        err = LucairnResponseValidationError("bad", body="not json at all")
        assert err.body == "not json at all"


class TestCatchability:
    """Callers can ``except LucairnError`` to catch all SDK-raised errors."""

    def test_catches_all_subclasses(self) -> None:
        for exc in (
            LucairnConfigError("x"),
            LucairnHttpError("x", status=500, body=None),
            LucairnTimeoutError("x"),
            LucairnCertificateError("x", reason="malformed"),
            LucairnResponseValidationError("x", body={}),
        ):
            try:
                raise exc
            except LucairnError as caught:
                assert caught is exc
            else:
                pytest.fail(f"did not catch {type(exc).__name__}")
