import type { ConflictError, Result } from '@/shared/kernel';
import type { InvalidMfaCodeError, MfaAlreadyEnrolledError } from './mfa-errors';

/** A TOTP factor of the user, as the Auth service reports it. Never carries the secret. */
export type TotpFactor = {
  readonly id: string;
  /** `true` once the user proved the factor with a code; until then it is only a candidate. */
  readonly verified: boolean;
  /**
   * The backend enrolled this factor (`POST /auth/mfa/totp/enroll`). A factor that is not was
   * created straight at the Auth service by someone holding the password and the publishable key
   * (F-60, F-61): the app never makes one, and the factor resolution ignores it.
   */
  readonly backendEnrolled: boolean;
};

/**
 * What a new factor gives the user to set up an authenticator app. It is shown ONCE (the contract's
 * `TotpEnrollment`): the secret and the URI are never stored, logged or returned again.
 */
export type TotpEnrollment = {
  readonly factorId: string;
  /** `otpauth://totp/...` URI for authenticator apps. Carries the secret. */
  readonly uri: string;
  /** The same secret in base32, for typing by hand. */
  readonly secret: string;
  /** QR code of the URI, as an SVG data URI. */
  readonly qrCode: string;
};

export type TotpCodeInput = {
  readonly factorId: string;
  /** Six digits, already validated. */
  readonly code: string;
};

/**
 * MFA of the user of the CURRENT request (Supabase Auth behind it). The session lives in cookies
 * the adapter manages: `verifyTotp` rewrites them with the `aal2` session, and the use cases never
 * see a token.
 *
 * Every method throws `ServiceUnavailableError` when the auth backend is slow or down (E-21): an
 * outage is not an answer about the code.
 */
export interface MfaGateway {
  /** The TOTP factors of the user, verified or not. Other factor types are not listed. */
  listTotpFactors(): Promise<readonly TotpFactor[]>;

  /** Deletes an UNVERIFIED factor (E-26). It never deletes a verified one. */
  removeUnverifiedTotp(factorId: string): Promise<void>;

  /**
   * Creates an unverified TOTP factor. `err(MfaAlreadyEnrolledError)` when the Auth service says a
   * verified factor exists (it wants `aal2` to add one); `err(ConflictError)` when the factors
   * changed while the call was in flight (a parallel enrollment): retrying is safe.
   */
  enrollTotp(): Promise<Result<TotpEnrollment, MfaAlreadyEnrolledError | ConflictError>>;

  /**
   * Burns the code (a replay of an accepted code inside 120 s is refused, F-21), challenges the
   * factor and answers the challenge with `code`. The first success activates the factor, and every
   * success replaces the session with an `aal2` one (new cookies).
   *
   * `recordChallenge` runs between the challenge and the answer: the backend must have recorded the
   * challenge it created BEFORE the Auth service can verify it (the attestation tells the backend's
   * challenges from the ones made straight at Auth, F-63). If it refuses, the challenge is never
   * answered; if it throws, so does this method.
   *
   * `err(InvalidMfaCodeError)` for a wrong or expired code, a replayed one, or a factor the account
   * does not own (the `reason` tells which, for the log). A code that was refused is burned too.
   * On success, `challengeId` is the challenge that was answered.
   */
  verifyTotp(
    input: TotpCodeInput & { readonly recordChallenge: RecordChallenge },
  ): Promise<Result<{ readonly challengeId: string }, InvalidMfaCodeError>>;

  /**
   * The id of the session of the current request, from the verified claims of its access token (an
   * `aal2` session keeps the id it had before the verification). Throws when it cannot be read:
   * nothing is attested for a session the backend cannot name.
   */
  currentSessionId(): Promise<string>;

  /**
   * Signs the user out of every session but the current one, whose cookies stay as they are. Used
   * when a verification activates the FIRST factor, so a session opened with a password alone (a
   * stolen one included, F-20) does not outlive the moment the account gets its second factor.
   * Throws when the Auth server answered with an error it does not treat as "already signed out".
   */
  revokeOtherSessions(): Promise<void>;
}

/** What the gateway calls with a challenge the backend has just created, before it is answered. */
export type RecordChallenge = (challengeId: string) => Promise<Result<void, InvalidMfaCodeError>>;

/**
 * Why the database refused to attest a session (`public.attest_mfa_session`). For the log and the
 * audit trail only: the response is always the same 422 `INVALID_MFA_CODE`.
 * - `oracle`: the factor has a challenge verified straight at Auth (not by the backend) inside the
 *   TOTP window: someone holding the password found a valid code there and replayed it (F-50 b);
 * - `factor_not_backend`, `factor_not_activated_by_backend`, `challenge_not_backend`: the factor or
 *   the challenge never went through the backend (F-61);
 * - the others: the ids the backend sent do not describe a consistent, fresh, verified `aal2`
 *   session of a CEO.
 */
export const ATTESTATION_REFUSALS = [
  'not_ceo',
  'session_not_found',
  'session_not_aal2',
  'factor_not_found',
  'factor_not_totp',
  'factor_not_verified',
  'factor_not_backend',
  'challenge_not_found',
  'challenge_not_verified',
  'challenge_stale',
  'challenge_not_backend',
  'oracle',
  'factor_not_activated_by_backend',
] as const;
export type AttestationRefusal = (typeof ATTESTATION_REFUSALS)[number];

export type AttestationOutcome =
  { readonly attested: true } | { readonly attested: false; readonly reason: AttestationRefusal };

/**
 * The backend's own records of what it did to MFA, kept by the database behind the `service_role`
 * (ADR 0013). It is not the user's session: the implementation uses the admin path, so the
 * user's session can never write to it.
 *
 * Every method throws `ServiceUnavailableError` when the database is slow or down and a plain error
 * for an answer it does not understand: nothing is attested on a failure (fail closed).
 */
export interface MfaAttestor {
  /**
   * Records a factor the enrollment has just created as the backend's own (F-60, F-61). `err` with
   * `ConflictError` when the factor is already gone (another enrollment replaced it): retrying is safe.
   */
  registerEnrollment(input: {
    readonly userId: string;
    readonly factorId: string;
    readonly sessionId: string;
  }): Promise<Result<void, ConflictError>>;

  /**
   * Records a challenge the backend has just created, before it is answered. `err` with
   * `InvalidMfaCodeError` (`factor_not_found`) when the database cannot find the factor or the
   * challenge for this user.
   */
  recordChallenge(input: {
    readonly userId: string;
    readonly factorId: string;
    readonly challengeId: string;
  }): Promise<Result<void, InvalidMfaCodeError>>;

  /**
   * Attests the session after a verification the Auth service accepted. The database revalidates
   * everything and, on a refusal, has already deleted every session of the user and audited it.
   */
  attest(input: {
    readonly userId: string;
    readonly sessionId: string;
    readonly factorId: string;
    readonly challengeId: string;
  }): Promise<AttestationOutcome>;
}
