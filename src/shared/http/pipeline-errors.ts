import { DomainError, type DomainErrorOptions, type ErrorCode } from '@/shared/kernel';

/**
 * Codes with their own error class, because their response has a mandatory extra member:
 * `VALIDATION_ERROR` (`errors[]`, `ValidationError`), `RATE_LIMITED` (`Retry-After`,
 * `RateLimitedError`) and `STALE_STAGE` (`currentStageId`, raised by the tracking module). A
 * `PipelineError` cannot carry them.
 */
type DedicatedCode = 'VALIDATION_ERROR' | 'RATE_LIMITED' | 'STALE_STAGE';

export type PipelineErrorCode = Exclude<ErrorCode, DedicatedCode>;

/**
 * A denial raised by a pipeline step (body, Origin…). `detail` is client-safe text written by
 * us, never upstream text.
 */
export class PipelineError extends DomainError {
  readonly code: PipelineErrorCode;

  constructor(code: PipelineErrorCode, message: string, options?: DomainErrorOptions) {
    super(message, options);
    this.code = code;
  }
}

/**
 * Why a request was refused by an access check. Logged in the `authz.denied` event; never sent to
 * the client, which only gets the `code`.
 */
export type AuthorizationDenialReason =
  'origin_not_allowed' | 'role_not_allowed' | `pending_action:${string}`;

/** A 403 raised by the Origin check or by the role/pending-action check. */
export class AuthorizationDeniedError extends PipelineError {
  readonly reason: AuthorizationDenialReason;

  constructor(code: PipelineErrorCode, reason: AuthorizationDenialReason, detail: string) {
    super(code, `access denied: ${reason}`, { detail });
    this.reason = reason;
  }
}

/** The rate limiter said no. Becomes 429 with `Retry-After`. */
export class RateLimitedError extends DomainError {
  readonly code = 'RATE_LIMITED';
  /** Whole seconds, at least 1. */
  readonly retryAfterSeconds: number;

  constructor(retryAfterSeconds: number) {
    super('rate limit exceeded', { detail: 'Too many requests. Try again later.' });
    this.retryAfterSeconds = retryAfterSeconds;
  }
}
