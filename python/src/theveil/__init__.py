"""Legacy import shim — ``theveil`` was renamed to ``lucairn``.

This package re-exports every public symbol from :mod:`lucairn` so that
existing ``from theveil import TheVeil`` (and equivalent) imports keep
working for one minor-version migration cycle. Update your imports to
``from lucairn import Lucairn`` (and equivalents) — the shim will be
removed in a future release.

Old name → new name mapping:

    TheVeil                          → Lucairn
    TheVeilConfig                    → LucairnConfig
    TheVeilError                     → LucairnError
    TheVeilConfigError               → LucairnConfigError
    TheVeilHttpError                 → LucairnHttpError
    TheVeilTimeoutError              → LucairnTimeoutError
    TheVeilCertificateError          → LucairnCertificateError
    TheVeilResponseValidationError   → LucairnResponseValidationError

The other re-exported symbols (``MessagesOptions``, ``ProxyResponse``,
``VeilCertificate``, etc.) keep their original names — only the
``TheVeil*`` identifiers were renamed.
"""

import warnings as _warnings

_warnings.warn(
    "The `theveil` package was renamed to `lucairn`. Update your imports "
    "to `from lucairn import Lucairn` (and equivalents). This shim will "
    "be removed in a future release.",
    DeprecationWarning,
    stacklevel=2,
)

# Re-export the renamed identifiers under their old names.
from lucairn import (  # noqa: F401, E402
    Lucairn as TheVeil,
    LucairnCertificateError as TheVeilCertificateError,
    LucairnConfig as TheVeilConfig,
    LucairnConfigError as TheVeilConfigError,
    LucairnError as TheVeilError,
    LucairnHttpError as TheVeilHttpError,
    LucairnResponseValidationError as TheVeilResponseValidationError,
    LucairnTimeoutError as TheVeilTimeoutError,
)

# Re-export the unchanged identifiers verbatim.
from lucairn import (  # noqa: F401, E402
    MessagesOptions,
    ProxyAcceptedResponse,
    ProxyMessagesRequest,
    ProxyPIIAnnotation,
    ProxyRequest,
    ProxyResponse,
    ProxySyncResponse,
    ProxyVeilReceipt,
    VeilAnchorStatusInfo,
    VeilCertificate,
    VeilClaim,
    VeilExternalAttestation,
    VeilVerificationResult,
    VerifyCertificateFailureReason,
    VerifyCertificateKeys,
    VerifyCertificateResult,
)

__all__ = [
    "MessagesOptions",
    "ProxyAcceptedResponse",
    "ProxyMessagesRequest",
    "ProxyPIIAnnotation",
    "ProxyRequest",
    "ProxyResponse",
    "ProxySyncResponse",
    "ProxyVeilReceipt",
    "TheVeil",
    "TheVeilCertificateError",
    "TheVeilConfig",
    "TheVeilConfigError",
    "TheVeilError",
    "TheVeilHttpError",
    "TheVeilResponseValidationError",
    "TheVeilTimeoutError",
    "VeilAnchorStatusInfo",
    "VeilCertificate",
    "VeilClaim",
    "VeilExternalAttestation",
    "VeilVerificationResult",
    "VerifyCertificateFailureReason",
    "VerifyCertificateKeys",
    "VerifyCertificateResult",
]

__version__ = "1.0.0"
