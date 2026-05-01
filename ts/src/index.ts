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
// re-exports keep existing code compiling. Removal scheduled for the next
// minor bump.
// ---------------------------------------------------------------------------
export { Lucairn as TheVeil } from './client.js';
export {
  LucairnError as TheVeilError,
  LucairnConfigError as TheVeilConfigError,
  LucairnHttpError as TheVeilHttpError,
  LucairnTimeoutError as TheVeilTimeoutError,
  LucairnCertificateError as TheVeilCertificateError,
} from './errors.js';
export type { LucairnConfig as TheVeilConfig } from './types.js';
