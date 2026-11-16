import { readCurrentPrincipal } from '@/shared/db/current-principal';
import type { RequestSupabase } from '@/shared/db/server-client';
import { isUpstreamUnavailable, upstreamFailure } from '@/shared/db/upstream-errors';
import { err, ok, ServiceUnavailableError } from '@/shared/kernel';
import {
  InvalidCredentialsError,
  UnexpectedAuthAnswerError,
  type CredentialsRefusal,
} from '../domain/errors';
import type { AuthGateway, PrincipalQuery } from '../domain/ports';

/**
 * The ONLY Auth answers that mean "these credentials do not open a session", by the error code of
 * the Auth server. They all become the same generic 401 (SEC-12); the value is the reason that goes
 * to the log.
 * - `invalid_credentials`: unknown e-mail or wrong password (Auth never says which);
 * - `user_banned`: banned in Auth (Wave 7 bans a login when a CEO disables it);
 * - `email_not_confirmed`: the e-mail was never confirmed.
 * Everything else the Auth server can answer is NOT about the credentials: see `signInWithPassword`.
 */
const CREDENTIAL_REFUSALS: ReadonlyMap<string, CredentialsRefusal> = new Map([
  ['invalid_credentials', 'invalid_credentials'],
  ['user_banned', 'account_inactive'],
  ['email_not_confirmed', 'account_inactive'],
]);

export type AuthGatewayOptions = {
  /**
   * The access token of the session `signOut` is about to end. When set, `signOut` does not trust
   * the Auth client's word that the session is gone: it asks the DATABASE (`current_principal()`
   * with this token) and fails if a principal still comes back. The Auth client treats a 401, 403
   * or 404 from the revocation call as "already signed out" and reports success even when nothing
   * was revoked, so without this check a logout could answer 204 with the session still alive.
   */
  readonly confirmRevocationOf?: string;
};

/**
 * Supabase Auth behind identity's ports, on the request-scoped client. The session cookies it
 * writes go through the jar of that client (`getRequestSupabase`), so the pipeline puts them on
 * the response.
 */
export function createSupabaseAuthGateway(
  supabase: RequestSupabase,
  options: AuthGatewayOptions = {},
): AuthGateway & PrincipalQuery {
  return {
    async signInWithPassword({ email, password }) {
      let result: Awaited<ReturnType<typeof supabase.auth.signInWithPassword>>;
      try {
        result = await supabase.auth.signInWithPassword({ email, password });
      } catch (cause) {
        throw upstreamFailure('sign in', cause);
      }

      const { data, error } = result;
      if (error) {
        // 1. The service, not the credentials: transport failure, timeout, a 5xx or a 429 from
        //    Auth. 503 (E-21), never a 401.
        if (isUpstreamUnavailable(error)) throw upstreamFailure('sign in', error);

        // 2. A known refusal of these credentials: the generic 401 (SEC-12).
        const code = typeof error.code === 'string' ? error.code : undefined;
        const refusal = code === undefined ? undefined : CREDENTIAL_REFUSALS.get(code);
        if (refusal !== undefined) return err(new InvalidCredentialsError(refusal));

        // 3. Anything else (an unknown error code, a 4xx about the request or the API key): the
        //    service is misconfigured or changed. It must NOT look like a wrong password, so it is
        //    a 503 that the log can tell apart.
        throw new UnexpectedAuthAnswerError(
          'sign in: the Auth server answered something unexpected',
          { status: error.status, code },
          { cause: error },
        );
      }
      // A successful sign-in always carries a session; without one nothing was opened.
      if (data.session === null) {
        throw new UnexpectedAuthAnswerError('sign in returned no session', {});
      }
      return ok(undefined);
    },

    async signOut() {
      let result: Awaited<ReturnType<typeof supabase.auth.signOut>>;
      try {
        // `local`: ends and revokes THIS session only (E-09). The default scope would sign the
        // user out of every device.
        result = await supabase.auth.signOut({ scope: 'local' });
      } catch (cause) {
        throw upstreamFailure('sign out', cause);
      }
      if (result.error) throw upstreamFailure('sign out', result.error);

      if (options.confirmRevocationOf !== undefined) {
        const stillAlive = await readCurrentPrincipal(supabase, {
          accessToken: options.confirmRevocationOf,
        });
        if (stillAlive !== null) {
          throw new ServiceUnavailableError(
            'sign out: the session is still alive after the logout',
          );
        }
      }
    },

    current() {
      return readCurrentPrincipal(supabase);
    },
  };
}
