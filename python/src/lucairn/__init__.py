from lucairn.client import Lucairn
from lucairn.errors import (
    LucairnCertificateError,
    LucairnConfigError,
    LucairnError,
    LucairnHttpError,
    LucairnResponseValidationError,
    LucairnTimeoutError,
)
from lucairn.verify_certificate.chain import (
    CertificateChainKeys,
    CertificateChainResult,
    verify_certificate_chain,
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

    The field is NOT part of the v2 signable (7 keys, UNCHANGED); it IS
    part of the v3 signable (13 keys) — see
    ``lucairn.verify_certificate.v3_signable``. When verifying against
    the v2 signable, treat the returned value as unsigned metadata;
    tamper evidence flows indirectly through the bridge claim's
    bridge-signed ``canonical_payload``.
    """

    return cert.client_id


__all__ = [
    "AuditEntry",
    "CertificateChainKeys",
    "CertificateChainResult",
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
    "verify_certificate_chain",
]

__version__ = "1.4.1"
