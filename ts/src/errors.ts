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

export type VerifyCertificateFailureReason =
  | 'malformed'
  | 'unsupported_protocol_version'
  | 'witness_mismatch'
  | 'witness_signature_missing'
  | 'invalid_signature';

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

/** @deprecated Use {@link LucairnCertificateError} instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export { LucairnCertificateError as TheVeilCertificateError };

/** @deprecated Use `LucairnCertificateErrorOptions` instead. The TheVeil* aliases will be removed in @lucairn/sdk@1.1.0. */
export type { LucairnCertificateErrorOptions as TheVeilCertificateErrorOptions };
