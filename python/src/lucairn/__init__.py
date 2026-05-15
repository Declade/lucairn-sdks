from lucairn.client import Lucairn
from lucairn.errors import (
    LucairnCertificateError,
    LucairnConfigError,
    LucairnError,
    LucairnHttpError,
    LucairnResponseValidationError,
    LucairnTimeoutError,
)
from lucairn.types import (
    AuditEntry,
    AuditExportOptions,
    AuditExportResponse,
    MessagesOptions,
    ProxyAcceptedResponse,
    ProxyMessagesRequest,
    ProxyPIIAnnotation,
    ProxyRequest,
    ProxyResponse,
    ProxySyncResponse,
    ProxyVeilReceipt,
    LucairnConfig,
    VeilAnchorStatusInfo,
    VeilCertificate,
    VeilClaim,
    VeilExternalAttestation,
    VeilVerificationResult,
    VerifyCertificateFailureReason,
    VerifyCertificateKeys,
    VerifyCertificateResult,
)


def get_client_id(cert: VeilCertificate) -> str | None:
    """Return ``cert.client_id`` (the org-scoped correlation field) or
    ``None`` if the certificate predates W2A-B1 or the gateway omitted
    the field.

    The field is unsigned metadata at the witness signable layer (see
    :class:`VeilCertificate` docstring); tamper evidence flows
    indirectly through the bridge claim's bridge-signed
    ``canonical_payload``.
    """

    return cert.client_id


__all__ = [
    "AuditEntry",
    "AuditExportOptions",
    "AuditExportResponse",
    "MessagesOptions",
    "ProxyAcceptedResponse",
    "ProxyMessagesRequest",
    "ProxyPIIAnnotation",
    "ProxyRequest",
    "ProxyResponse",
    "ProxySyncResponse",
    "ProxyVeilReceipt",
    "Lucairn",
    "LucairnCertificateError",
    "LucairnConfig",
    "LucairnConfigError",
    "LucairnError",
    "LucairnHttpError",
    "LucairnResponseValidationError",
    "LucairnTimeoutError",
    "VeilAnchorStatusInfo",
    "VeilCertificate",
    "VeilClaim",
    "VeilExternalAttestation",
    "VeilVerificationResult",
    "VerifyCertificateFailureReason",
    "VerifyCertificateKeys",
    "VerifyCertificateResult",
    "get_client_id",
]

__version__ = "1.1.2"
