import { DomainError } from '@/shared/kernel';

/**
 * Why a TOTP code was refused, for the LOG only (`auth.mfa.failed`). It is never part of the
 * response: the client always gets the same 422.
 * - `invalid_code`: the Auth server says the code is wrong or expired;
 * - `code_reused`: the same code of the same factor was already accepted in the last 120 s (replay,
 *   F-21): it never reaches the Auth server;
 * - `factor_not_found`: the factor is not a TOTP factor of this account (another user's, one that
 *   was removed, or an id nobody has), or, when the request names no factor, the account has none.
 *   It is how a stale tab after E-26 looks, and also how an attacker who replaced the CEO's
 *   unfinished factor (F-20) shows up when the CEO tries it;
 * - `factor_ambiguous`: the request names no factor and the account has more than one TOTP factor
 *   in the same state (E-31), so the session does not say which one is meant. The enrollment never
 *   leaves such an account behind; the code is not tried on any of them.
 */
export type MfaRefusal = 'invalid_code' | 'code_reused' | 'factor_not_found' | 'factor_ambiguous';

export type InvalidMfaCodeOptions = ErrorOptions & {
  /** The factor the code was meant for, when there is one. For the log only. */
  readonly factorId?: string;
};

/**
 * The TOTP code was refused: wrong, expired, already used, or aimed at a factor this account does
 * not have. The response is the SAME in every one of those cases (422 `INVALID_MFA_CODE`, E-28), so
 * a caller cannot probe which factor ids exist nor which codes were used. It counts against the
 * verification rate limits like any other attempt (the limits are on the route, not on the failure).
 */
export class InvalidMfaCodeError extends DomainError {
  readonly code = 'INVALID_MFA_CODE';
  readonly reason: MfaRefusal;
  /** The factor the code was meant for (never part of the response), if one was resolved. */
  readonly factorId: string | undefined;

  constructor(reason: MfaRefusal = 'invalid_code', options: InvalidMfaCodeOptions = {}) {
    const { factorId, ...errorOptions } = options;
    super('the TOTP code was refused', {
      ...errorOptions,
      detail: 'The code is invalid or has expired.',
    });
    this.reason = reason;
    this.factorId = factorId;
  }
}

/** A CEO who already has a verified TOTP factor tried to enroll another one (E-27). */
export class MfaAlreadyEnrolledError extends DomainError {
  readonly code = 'MFA_ALREADY_ENROLLED';

  constructor(options?: ErrorOptions) {
    super('a verified TOTP factor already exists', {
      ...options,
      detail: 'An authenticator app is already registered for this account.',
    });
  }
}
