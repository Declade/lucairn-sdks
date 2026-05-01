export { Lucairn } from './client.js';
export { getClientId } from './client-id.js';
export {
  LucairnError,
  LucairnConfigError,
  LucairnHttpError,
  LucairnTimeoutError,
  LucairnCertificateError,
} from './errors.js';
export type { VerifyCertificateFailureReason } from './errors.js';
export type {
  AuditEntry,
  AuditExportResponse,
  ListAuditEventsOptions,
  LucairnConfig,
  ProxyRequest,
  ProxyResponse,
  ProxySyncResponse,
  ProxyAcceptedResponse,
  ProxyJobStatus,
  ProxyVeilReceipt,
  ProxyPIIAnnotation,
  ProxyMessagesRequest,
  MessagesOptions,
  VeilCertificate,
  VeilClaim,
  VeilVerificationResult,
  VeilAnchorStatusInfo,
  VeilExternalAttestation,
  VeilCertAnchorStatus,
  VeilVerdict,
  VeilCompleteness,
  VeilClaimType,
  VeilIsolationProbeStatus,
  VerifyCertificateKeys,
  VerifyCertificateResult,
} from './types.js';

// ---------------------------------------------------------------------------
// Legacy aliases — one minor-version migration cycle.
// Pre-Stage-3 callers imported `TheVeil` and `TheVeil*Error` names; these
// re-exports keep existing code compiling. Removal scheduled for
// @lucairn/sdk@1.1.0. Each alias carries an @deprecated JSDoc tag so VS Code
// and other JSDoc-aware editors render strikethrough on legacy usages.
// ---------------------------------------------------------------------------

/** @deprecated Use {@link Lucairn} instead. The TheVeil aliases will be removed in @lucairn/sdk@1.1.0. */
export { Lucairn as TheVeil } from './client.js';

/** @deprecated Use {@link LucairnError} instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export { LucairnError as TheVeilError } from './errors.js';

/** @deprecated Use {@link LucairnConfigError} instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export { LucairnConfigError as TheVeilConfigError } from './errors.js';

/** @deprecated Use {@link LucairnHttpError} instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export { LucairnHttpError as TheVeilHttpError } from './errors.js';

/** @deprecated Use {@link LucairnTimeoutError} instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export { LucairnTimeoutError as TheVeilTimeoutError } from './errors.js';

/** @deprecated Use {@link LucairnCertificateError} instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export { LucairnCertificateError as TheVeilCertificateError } from './errors.js';

/** @deprecated Use `LucairnConfig` instead. The TheVeilConfig alias will be removed in @lucairn/sdk@1.1.0. */
export type { LucairnConfig as TheVeilConfig } from './types.js';
