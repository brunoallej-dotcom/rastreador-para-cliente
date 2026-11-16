import { DomainError } from '@/shared/kernel';

/**
 * Why a TOTP code was refused, for the LOG only (`auth.mfa.failed`). It is never part of the
 * response: the client always gets the same 422.
 * - `invalid_code`: the Auth server says the code is wrong or expired;
 * - `code_reused`: the same code of the same factor was already accepted in the last 120 s (replay,
 *   F-21): it never reaches the Auth server;
 * - `factor_not_found`: the factor is not a TOTP factor of this account (another user's, one that
 *   was removed, or an id nobody has). It is how a stale tab after E-26 looks, and also how an
 *   attacker who replaced the CEO's unfinished factor (F-20) shows up when the CEO tries it.
 */
export type MfaRefusal = 'invalid_code' | 'code_reused' | 'factor_not_found';

/**
 * The TOTP code was refused: wrong, expired, already used, or aimed at a factor this account does
 * not have. The response is the SAME in every one of those cases (422 `INVALID_MFA_CODE`, E-28), so
 * a caller cannot probe which factor ids exist nor which codes were used. It counts against the
 * verification rate limits like any other attempt (the limits are on the route, not on the failure).
 */
export class InvalidMfaCodeError extends DomainError {
  readonly code = 'INVALID_MFA_CODE';
  readonly reason: MfaRefusal;

  constructor(reason: MfaRefusal = 'invalid_code', options?: ErrorOptions) {
    super('the TOTP code was refused', {
      ...options,
      detail: 'The code is invalid or has expired.',
    });
    this.reason = reason;
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
