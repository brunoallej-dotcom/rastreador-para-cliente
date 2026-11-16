import type { ForbiddenError, Result } from '@/shared/kernel';
import type {
  InvalidCurrentPasswordError,
  PasswordUnchangedError,
  WeakPasswordError,
} from './password-errors';
import type { PasswordChange } from './password-policy';

/**
 * Changing the password of the user of the CURRENT request. The session is the one the pipeline
 * authenticated and lives in the request's cookies, which the adapter manages; the use case never
 * sees a token, an e-mail or a hash.
 *
 * Every method throws `ServiceUnavailableError` when the auth backend is slow or down (E-21)
 * instead of returning a result: an outage is not an answer about the password.
 */
export interface PasswordGateway {
  /**
   * Proves the user knows the CURRENT password, without touching the session of this request.
   * `err(InvalidCurrentPasswordError)` when the backend says the credentials are wrong.
   */
  verifyCurrentPassword(
    currentPassword: string,
  ): Promise<Result<void, InvalidCurrentPasswordError>>;

  /**
   * Stores the new password in the auth backend, keeping the session of this request alive. Refusals
   * the backend can still make after the use case's own checks become results: it judges the
   * password too weak, finds it equal to the current one, or finds the current one wrong.
   */
  updatePassword(
    change: PasswordChange,
  ): Promise<
    Result<void, InvalidCurrentPasswordError | WeakPasswordError | PasswordUnchangedError>
  >;

  /**
   * Calls `public.mark_password_changed()` (spec §3.7): the database checks that the password really
   * changed (ADR 0007), clears the pending `CHANGE_PASSWORD` and revokes the user's OTHER sessions.
   * `err(PasswordUnchangedError)` when it finds no proof of a change; `err(ForbiddenError)` when it
   * refuses the caller (a CEO with a verified second factor on an `aal1` session).
   */
  markPasswordChanged(): Promise<Result<void, PasswordUnchangedError | ForbiddenError>>;
}
