import type { ConflictError, Result } from '@/shared/kernel';
import type { InvalidMfaCodeError, MfaAlreadyEnrolledError } from './mfa-errors';

/** A TOTP factor of the user, as the Auth service reports it. Never carries the secret. */
export type TotpFactor = {
  readonly id: string;
  /** `true` once the user proved the factor with a code; until then it is only a candidate. */
  readonly verified: boolean;
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
   * `err(InvalidMfaCodeError)` for a wrong or expired code, a replayed one, or a factor the account
   * does not own (the `reason` tells which, for the log). A code that was refused is burned too.
   */
  verifyTotp(input: TotpCodeInput): Promise<Result<void, InvalidMfaCodeError>>;

  /**
   * Signs the user out of every session but the current one, whose cookies stay as they are. Used
   * when a verification activates the FIRST factor, so a session opened with a password alone (a
   * stolen one included, F-20) does not outlive the moment the account gets its second factor.
   * Throws when the Auth server answered with an error it does not treat as "already signed out".
   */
  revokeOtherSessions(): Promise<void>;
}
