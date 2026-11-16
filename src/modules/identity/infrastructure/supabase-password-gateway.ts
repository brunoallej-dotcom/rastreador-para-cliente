import type { RequestSupabase } from '@/shared/db/server-client';
import { isUpstreamUnavailable, upstreamFailure } from '@/shared/db/upstream-errors';
import { err, ForbiddenError, ok } from '@/shared/kernel';
import type { Logger } from '@/shared/observability/logger';
import { UnexpectedAuthAnswerError } from '../domain/errors';
import {
  InvalidCurrentPasswordError,
  PasswordUnchangedError,
  WeakPasswordError,
} from '../domain/password-errors';
import type { PasswordGateway } from '../domain/password-ports';
import type { ReauthClient } from './reauth-client';

/**
 * The Auth answers that mean "this is not the user's password", by the error code of the Auth
 * server: the three of a sign-in (the same ones the login maps to its generic 401) and the two a
 * password update makes when the project requires the current password. They all become
 * `InvalidCurrentPasswordError`. Anything else is NOT about the password: see `verifyCurrentPassword`.
 *
 * `current_password_mismatch` and `current_password_required` are codes of the GoTrue server
 * (`ErrorCodeCurrentPasswordMismatch` and `ErrorCodeCurrentPasswordRequired`, answered with a 400
 * when `security_update_password_require_current_password` is on); the installed `@supabase/auth-js`
 * (2.119.0) does not list them in its `ErrorCode` union. That is why the codes are compared as plain
 * strings here and why the unit tests pin them by value: a type check cannot notice a rename.
 */
const WRONG_PASSWORD_CODES: ReadonlySet<string> = new Set([
  'invalid_credentials',
  'user_banned',
  'email_not_confirmed',
  'current_password_mismatch',
  'current_password_required',
]);

/** Postgres: `insufficient_privilege`, what the database functions raise for a denied caller. */
const INSUFFICIENT_PRIVILEGE = '42501';
/** Postgres: `raise_exception`, with the application code as the message (spec §3.7). */
const RAISE_EXCEPTION = 'P0001';
const PASSWORD_UNCHANGED_MESSAGE = 'PASSWORD_UNCHANGED';

export type PasswordGatewayOptions = {
  /** Where the password is proven: a throwaway client with no session (see `createReauthClient`). */
  readonly reauth: ReauthClient;
  readonly logger: Pick<Logger, 'warn'>;
  /**
   * Awaited right before the sign-in that proves the password, outside its error handling: the
   * handler spends the global login budget here (the sign-in is a call to Auth like a login), and
   * what it throws (a 429) must reach the pipeline as it is.
   */
  readonly beforeReauthentication?: () => Promise<void>;
};

const codeOf = (error: { code?: unknown }): string | undefined =>
  typeof error.code === 'string' ? error.code : undefined;

/**
 * Password change on Supabase, behind identity's port. The request-scoped client is the user's own
 * session (the same one the pipeline's resolver used, ADR 0002): the update and the database call
 * are made with it, and the cookies it writes go through the pipeline's jar into the response.
 *
 * Why the current password is proven by signing in (ADR 0010): the Auth server only enforces the
 * current password in `updateUser` when the project turns on `security_update_password_require_current_password`,
 * a setting of the hosted project that the local stack cannot set and that is off here (verified:
 * a wrong `current_password` is ignored). So the gateway checks it itself, on a throwaway client,
 * and also hands `current_password` to the update, so a project that does enforce it enforces it twice.
 */
export function createSupabasePasswordGateway(
  supabase: RequestSupabase,
  options: PasswordGatewayOptions,
): PasswordGateway {
  /** The e-mail of the session's user, from the verified claims of the access token. */
  async function emailOfSession(): Promise<string> {
    let result: Awaited<ReturnType<typeof supabase.auth.getClaims>>;
    try {
      result = await supabase.auth.getClaims();
    } catch (cause) {
      throw upstreamFailure('read the session claims', cause);
    }
    if (result.error) throw upstreamFailure('read the session claims', result.error);
    const email: unknown = result.data?.claims.email;
    // An authenticated request always has a session whose token carries the e-mail; without it the
    // password cannot be proven, so the change is refused (fail closed, 500).
    if (typeof email !== 'string' || email === '') {
      throw new Error('the session token carries no e-mail');
    }
    return email;
  }

  /** Ends the throwaway session. Best effort: see the comment at the call. */
  async function revokeProbeSession(reauth: ReauthClient): Promise<void> {
    try {
      const { error } = await reauth.auth.signOut({ scope: 'local' });
      if (error) throw error;
    } catch {
      // The tokens of this session never left this process, and the Auth server drops every other
      // session of the user when the password is updated, and `mark_password_changed()` does it
      // again. Failing the request here would not make the session any deader.
      options.logger.warn(
        { event: 'auth.password_change.probe_session_not_revoked' },
        'auth.password_change.probe_session_not_revoked',
      );
    }
  }

  return {
    async verifyCurrentPassword(currentPassword) {
      const email = await emailOfSession();
      await options.beforeReauthentication?.();

      let result: Awaited<ReturnType<ReauthClient['auth']['signInWithPassword']>>;
      try {
        result = await options.reauth.auth.signInWithPassword({ email, password: currentPassword });
      } catch (cause) {
        throw upstreamFailure('verify the current password', cause);
      }

      const { data, error } = result;
      if (error) {
        // 1. The service, not the password: transport failure, timeout, a 5xx or a 429 from Auth.
        if (isUpstreamUnavailable(error))
          throw upstreamFailure('verify the current password', error);

        // 2. A known refusal of these credentials.
        const code = codeOf(error);
        if (code !== undefined && WRONG_PASSWORD_CODES.has(code)) {
          return err(new InvalidCurrentPasswordError());
        }

        // 3. Anything else: the service is misconfigured or changed. It must NOT look like a wrong
        //    password, so it is a 503 that the log can tell apart.
        throw new UnexpectedAuthAnswerError(
          'verify the current password: the Auth server answered something unexpected',
          { status: error.status, code },
          { cause: error },
        );
      }

      // The sign-in opened a session of its own. It is ended now, before anything else, whatever
      // the answer says: a session that nobody can use should not outlive the check.
      await revokeProbeSession(options.reauth);
      if (data.session === null) {
        throw new UnexpectedAuthAnswerError('verify the current password returned no session', {});
      }
      return ok(undefined);
    },

    async updatePassword({ currentPassword, newPassword }) {
      let result: Awaited<ReturnType<typeof supabase.auth.updateUser>>;
      try {
        result = await supabase.auth.updateUser({
          password: newPassword,
          current_password: currentPassword,
        });
      } catch (cause) {
        throw upstreamFailure('update the password', cause);
      }

      const { error } = result;
      if (!error) return ok(undefined);

      if (isUpstreamUnavailable(error)) throw upstreamFailure('update the password', error);

      const code = codeOf(error);
      if (code === 'same_password') return err(new PasswordUnchangedError());
      if (code === 'weak_password') return err(new WeakPasswordError());
      if (code !== undefined && WRONG_PASSWORD_CODES.has(code)) {
        return err(new InvalidCurrentPasswordError());
      }
      // Includes `reauthentication_needed` (a session older than 24 h under `secure_password_change`,
      // which sessions of at most 12 h never are) and any new code: a problem of the service.
      throw new UnexpectedAuthAnswerError(
        'update the password: the Auth server answered something unexpected',
        { status: error.status, code },
        { cause: error },
      );
    },

    async markPasswordChanged() {
      const { error, status } = await supabase.rpc('mark_password_changed');
      if (!error) return ok(undefined);

      if (error.code === INSUFFICIENT_PRIVILEGE) {
        // Layer 1 should have stopped this caller: a denial here means it was bypassed (spec §3.7).
        options.logger.warn(
          { event: 'authz.database_denied', operation: 'mark_password_changed' },
          'authz.database_denied',
        );
        return err(new ForbiddenError('mark_password_changed denied the caller'));
      }
      if (error.code === RAISE_EXCEPTION && error.message === PASSWORD_UNCHANGED_MESSAGE) {
        return err(new PasswordUnchangedError('mark_password_changed found no change'));
      }
      throw upstreamFailure('mark the password as changed', error, status);
    },
  };
}
