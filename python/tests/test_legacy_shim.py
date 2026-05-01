"""Verify the legacy ``theveil`` shim re-exports the renamed identifiers
under their old names and emits a DeprecationWarning at import time.

This test is intentionally minimal — full behavioural coverage lives on
the new ``lucairn`` import path; the shim's only job is to keep existing
``from theveil import ...`` callers working for one migration cycle.
"""

from __future__ import annotations

import importlib
import sys
import warnings


def _reimport_shim():
    """Force a fresh import so the DeprecationWarning fires this run."""

    sys.modules.pop("theveil", None)
    return importlib.import_module("theveil")


def test_shim_emits_deprecation_warning() -> None:
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        _reimport_shim()
    matches = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert matches, "Expected DeprecationWarning on `import theveil`"
    assert "lucairn" in str(matches[0].message).lower()


def test_shim_aliases_resolve_to_new_classes() -> None:
    shim = _reimport_shim()
    import lucairn

    # Renamed identifiers — shim alias must `is` the new class object.
    assert shim.TheVeil is lucairn.Lucairn
    assert shim.TheVeilConfig is lucairn.LucairnConfig
    assert shim.TheVeilError is lucairn.LucairnError
    assert shim.TheVeilConfigError is lucairn.LucairnConfigError
    assert shim.TheVeilHttpError is lucairn.LucairnHttpError
    assert shim.TheVeilTimeoutError is lucairn.LucairnTimeoutError
    assert shim.TheVeilCertificateError is lucairn.LucairnCertificateError
    assert (
        shim.TheVeilResponseValidationError
        is lucairn.LucairnResponseValidationError
    )


def test_shim_passthrough_identifiers_unchanged() -> None:
    shim = _reimport_shim()
    import lucairn

    # Unchanged identifiers are re-exported verbatim.
    assert shim.MessagesOptions is lucairn.MessagesOptions
    assert shim.VeilCertificate is lucairn.VeilCertificate
    assert shim.VerifyCertificateKeys is lucairn.VerifyCertificateKeys


def test_shim_legacy_construction_works() -> None:
    shim = _reimport_shim()

    valid_key = "dsa_" + "0" * 32
    client = shim.TheVeil(shim.TheVeilConfig(api_key=valid_key))
    assert isinstance(client, shim.TheVeil)
    # Sanity: the client is usable through the shim alias.
    assert client.base_url.startswith("https://")
