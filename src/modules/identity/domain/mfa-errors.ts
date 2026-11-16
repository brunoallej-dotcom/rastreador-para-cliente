import { DomainError } from '@/shared/kernel';
import type { AttestationRefusal } from './mfa-ports';

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
 * - `factor_ambiguous`: the request names no factor and the backend enrolled more than one TOTP
 *   factor of the account in the same state (E-31), so the session does not say which one is meant.
 *   The enrollment never leaves such an account behind (and a factor planted straight at Auth is not
 *   counted, F-60); the code is not tried on any of them;
 * - `attestation_refused`: the Auth service accepted the code, but the database refused to attest the
 *   session (F-50 b, F-61): see `attestationReason`. Every session of the user was deleted. It is an
 *   alert, not a typo.
 */
export type MfaRefusal =
  'invalid_code' | 'code_reused' | 'factor_not_found' | 'factor_ambiguous' | 'attestation_refused';

export type InvalidMfaCodeOptions = ErrorOptions & {
  /** The factor the code was meant for, when there is one. For the log only. */
  readonly factorId?: string;
  /**
   * How many TOTP factors the account has, when the request named none and they were listed. The
   * app keeps exactly one, so more than one is anomalous (F-60, F-61). For the log only.
   */
  readonly candidateCount?: number;
  /**
   * How many of those factors the backend did not enroll (created straight at Auth, F-60, F-61).
   * The app never makes one, so a value above zero is an alert. For the log only.
   */
  readonly foreignFactorCount?: number;
  /** Why the database refused to attest the session (`attestation_refused`). For the log only. */
  readonly attestationReason?: AttestationRefusal;
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
  /** How many TOTP factors the account has, when they were listed (never part of the response). */
  readonly candidateCount: number | undefined;
  /** How many of them the backend did not enroll, when they were listed (never part of the response). */
  readonly foreignFactorCount: number | undefined;
  /** Why the attestation was refused, for `attestation_refused` (never part of the response). */
  readonly attestationReason: AttestationRefusal | undefined;

  constructor(reason: MfaRefusal = 'invalid_code', options: InvalidMfaCodeOptions = {}) {
    const { factorId, candidateCount, foreignFactorCount, attestationReason, ...errorOptions } =
      options;
    super('the TOTP code was refused', {
      ...errorOptions,
      detail: 'The code is invalid or has expired.',
    });
    this.reason = reason;
    this.factorId = factorId;
    this.candidateCount = candidateCount;
    this.foreignFactorCount = foreignFactorCount;
    this.attestationReason = attestationReason;
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
