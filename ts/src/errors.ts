export class LucairnError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'LucairnError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class LucairnConfigError extends LucairnError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'LucairnConfigError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class LucairnHttpError extends LucairnError {
  public readonly status: number;
  public readonly body: unknown;

  constructor(message: string, status: number, body: unknown, options?: ErrorOptions) {
    super(message, options);
    this.name = 'LucairnHttpError';
    this.status = status;
    this.body = body;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class LucairnTimeoutError extends LucairnError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'LucairnTimeoutError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export interface LucairnResponseValidationErrorOptions extends ErrorOptions {
  // Raw deserialized 2xx body — a parsed object/array/primitive when the
  // response was JSON, or the raw text otherwise. Surfaced for diagnostics.
  body: unknown;
}

/**
 * Raised when a 2xx gateway response deserializes into a shape that does not
 * fit the SDK's declared response type — either a non-JSON body, a JSON body
 * missing required fields, or a body that overflowed the configured
 * `maxResponseBytes` cap.
 *
 * Distinct from {@link LucairnHttpError}, which is reserved for non-2xx
 * responses and the 202 pending wrapper on `getCertificate`. A response-
 * validation error means "the gateway replied with apparent success, but the
 * body we got doesn't look like the declared type" — typically a gateway bug
 * or version skew, not a transport failure.
 *
 * Parity: mirrors `LucairnResponseValidationError` (Python) and
 * `ResponseValidationError` (Go), closing the CON-02 robustness gap.
 */
export class LucairnResponseValidationError extends LucairnError {
  // Raw deserialized 2xx body for diagnostics. UNVERIFIED untrusted input —
  // consumers logging this should escape / truncate / bound length.
  public readonly body: unknown;

  constructor(message: string, options: LucairnResponseValidationErrorOptions) {
    super(message, options);
    this.name = 'LucairnResponseValidationError';
    this.body = options.body;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export type VerifyCertificateFailureReason =
  | 'malformed'
  | 'unsupported_protocol_version'
  | 'witness_mismatch'
  | 'witness_signature_missing'
  | 'invalid_signature'
  /**
   * A v3 signature (`signable_v3_signature`) was present on the certificate
   * but the version field (`signable_protocol_version_emitted`) was absent or
   * below 3, which would silently downgrade verification to the v2 path and
   * leave v3-only fields (api_key_id, client_id, byok_exempt, and the
   * sanitizer hash fields) unverified while returning `valid=true`.
   *
   * Legitimate v3 certs always carry `signable_protocol_version_emitted >= 3`.
   * Legitimate v2-only certs never carry `signable_v3_signature`. The only
   * path that triggers this reason is a tampered cert where an attacker has
   * stripped the version field to force the v2 path.
   *
   * @see TOB-SDK-TS-01 (ToB review, 2026-06)
   */
  | 'version_downgrade_detected'
  /**
   * Thrown when `options.minimumSignableVersion` is `'v3'` but the resolved
   * signable version is `'v2'`. Callers that rely on v3-only fields for
   * security decisions (api_key_id, client_id, byok_exempt, sanitizer hashes)
   * should pass `{ minimumSignableVersion: 'v3' }` to ensure they never
   * silently accept a v2-verified cert where those fields are not
   * witness-signed.
   *
   * @see TOB-SDK-TS-01 (ToB review, 2026-06)
   */
  | 'signable_version_insufficient';

export interface LucairnCertificateErrorOptions extends ErrorOptions {
  reason: VerifyCertificateFailureReason;
  certificateId?: string;
}

export class LucairnCertificateError extends LucairnError {
  public readonly reason: VerifyCertificateFailureReason;

  /**
   * Certificate ID lifted from `cert.certificate_id` for error-context
   * logging. SECURITY NOTE: on all failure paths, this value is UNVERIFIED —
   * the witness signature has not yet been (or failed to) verify by the
   * time this ID is attached. An attacker or malformed cert can set any
   * string here. Consumers logging this field should treat it as untrusted
   * input (escape / truncate / bound length). Only on the success return
   * path (VerifyCertificateResult.certificateId) is this value covered by
   * the witness signature.
   */
  public readonly certificateId?: string;

  constructor(message: string, options: LucairnCertificateErrorOptions) {
    super(message, options);
    this.name = 'LucairnCertificateError';
    this.reason = options.reason;
    this.certificateId = options.certificateId;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ---------------------------------------------------------------------------
// Legacy aliases — one minor-version migration cycle.
// Pre-Stage-3 callers imported `TheVeil*Error` names; these re-exports keep
// existing code compiling. Removal is scheduled for @lucairn/sdk@1.1.0. Each
// alias carries an @deprecated JSDoc tag so VS Code and other JSDoc-aware
// editors render strikethrough on legacy usages.
// ---------------------------------------------------------------------------

/** @deprecated Use {@link LucairnError} instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export { LucairnError as TheVeilError };

/** @deprecated Use {@link LucairnConfigError} instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export { LucairnConfigError as TheVeilConfigError };

/** @deprecated Use {@link LucairnHttpError} instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export { LucairnHttpError as TheVeilHttpError };

/** @deprecated Use {@link LucairnTimeoutError} instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export { LucairnTimeoutError as TheVeilTimeoutError };

/** @deprecated Use {@link LucairnResponseValidationError} instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export { LucairnResponseValidationError as TheVeilResponseValidationError };

/** @deprecated Use `LucairnResponseValidationErrorOptions` instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export type { LucairnResponseValidationErrorOptions as TheVeilResponseValidationErrorOptions };

/** @deprecated Use {@link LucairnCertificateError} instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export { LucairnCertificateError as TheVeilCertificateError };

/** @deprecated Use `LucairnCertificateErrorOptions` instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export type { LucairnCertificateErrorOptions as TheVeilCertificateErrorOptions };
