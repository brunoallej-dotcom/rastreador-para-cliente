import type { ConflictError, Result } from '@/shared/kernel';
import type {
  InvalidMfaCodeError,
  MfaAlreadyEnrolledError,
  MfaReenrollmentRefusedError,
} from './mfa-errors';

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
   * `burnCode` receives the digest of the code (a PostgREST `bytea` literal, never the code) and
   * runs FIRST: the replay guard lives behind the admin path now (F-65), so the gateway cannot burn
   * with the user's session. `recordChallenge` runs between the challenge and the answer: the backend
   * must have recorded the challenge it created BEFORE the Auth service can verify it (the
   * attestation tells the backend's challenges from the ones made straight at Auth, F-63). If either
   * refuses, nothing after it runs; if either throws, so does this method.
   *
   * `err(InvalidMfaCodeError)` for a wrong or expired code, a replayed one, or a factor the account
   * does not own (the `reason` tells which, for the log). A code that was refused is burned too.
   * On success, `challengeId` is the challenge that was answered.
   */
  verifyTotp(
    input: TotpCodeInput & {
      readonly burnCode: BurnCode;
      readonly recordChallenge: RecordChallenge;
    },
  ): Promise<Result<{ readonly challengeId: string }, InvalidMfaCodeError>>;

  /**
   * The id of the session of the current request, from the verified claims of its access token (an
   * `aal2` session keeps the id it had before the verification). Throws when it cannot be read:
   * nothing is attested for a session the backend cannot name.
   */
  currentSessionId(): Promise<string>;
}

/**
 * What the gateway calls with the digest of the code, before anything else: `ok` the first time the code
 * is seen, `err(InvalidMfaCodeError)` for a replay (`code_reused`) or a factor the account does not
 * own (`factor_not_found`).
 */
export type BurnCode = (codeDigest: string) => Promise<Result<void, InvalidMfaCodeError>>;

/** What the gateway calls with a challenge the backend has just created, before it is answered. */
export type RecordChallenge = (challengeId: string) => Promise<Result<void, InvalidMfaCodeError>>;

/**
 * Why the database refused to attest a session (`public.attest_mfa_session`). For the log and the
 * audit trail only: the response is always the same 422 `INVALID_MFA_CODE`.
 * - `oracle`: the factor has a challenge verified straight at Auth (not by the backend) inside the
 *   TOTP window: someone holding the password found a valid code there and replayed it (F-50 b);
 * - `factor_not_backend`, `factor_not_activated_by_backend`, `challenge_not_backend`: the factor or
 *   the challenge never went through the backend (F-61);
 * - `factor_reenrolled`: the account already had its first factor activated and this is a new one (the
 *   old one was deleted at Auth, F-64);
 * - `challenge_reused`, `session_factor_mismatch`, `challenge_not_found`: a challenge or a session that
 *   is not the one the backend just verified (F-67);
 * - the others: the ids the backend sent do not describe a consistent, fresh,
 *   verified `aal2` session of a CEO. Anyone can cause them by a race, so they refuse without
 *   revoking (F-66).
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
  'session_factor_mismatch',
  'challenge_reused',
  'factor_reenrolled',
] as const;
export type AttestationRefusal = (typeof ATTESTATION_REFUSALS)[number];

/**
 * The refusals that are SIGNS OF AN ATTACK: the database deleted every session of the user (and the
 * log is an alert). The other reasons are races and inconsistencies that refuse without revoking
 * (F-66). The list mirrors `private.refuse_mfa_attestation`; a unit test pins both.
 */
export const ATTESTATION_ATTACK_SIGNALS: ReadonlySet<AttestationRefusal> = new Set([
  'oracle',
  'factor_not_backend',
  'factor_not_activated_by_backend',
  'challenge_not_backend',
  'challenge_not_found',
  'challenge_reused',
  'session_factor_mismatch',
  'factor_reenrolled',
]);

export type AttestationOutcome =
  | {
      readonly attested: true;
      /**
       * This attestation ACTIVATED the first factor of the user (`attested_activated`): the database
       * derived it, so it is true on the retry after a failed attestation too (F-72). The other sessions
       * of the CEO are signed out then (F-20), whatever the pending actions said.
       */
      readonly activated: boolean;
    }
  | { readonly attested: false; readonly reason: AttestationRefusal };

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
   * `err` with `MfaReenrollmentRefusedError` when the user already had a first factor activated and
   * it was deleted behind the backend's back (F-64): the database deleted every session of the user.
   */
  registerEnrollment(input: {
    readonly userId: string;
    readonly factorId: string;
    readonly sessionId: string;
  }): Promise<Result<void, ConflictError | MfaReenrollmentRefusedError>>;

  /**
   * Burns a TOTP code (F-21, F-65): `ok` the first time, `err(InvalidMfaCodeError)` `code_reused` for a
   * replay inside 120 s and `factor_not_found` for a factor the user does not own. It is the admin path's
   * job, not the user's session's: with the user's session it was an oracle for the codes.
   */
  burnCode(input: {
    readonly userId: string;
    readonly factorId: string;
    readonly codeDigest: string;
  }): Promise<Result<void, InvalidMfaCodeError>>;

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
