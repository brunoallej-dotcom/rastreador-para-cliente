import { readCurrentPrincipal } from '@/shared/db/current-principal';
import type { RequestSupabase } from '@/shared/db/server-client';
import { isUpstreamUnavailable, upstreamFailure } from '@/shared/db/upstream-errors';
import { err, ok, ServiceUnavailableError } from '@/shared/kernel';
import { InvalidCredentialsError } from '../domain/errors';
import type { AuthGateway, PrincipalQuery } from '../domain/ports';

const CLIENT_ERROR_MIN_STATUS = 400;
const CLIENT_ERROR_MAX_STATUS = 499;
const TOO_MANY_REQUESTS_STATUS = 429;

/**
 * An answer from the Auth server that says "no" to these credentials. Every 4xx counts, whatever
 * its code (`invalid_credentials`, `email_not_confirmed`, `user_banned`...), so the client cannot
 * tell the reasons apart (SEC-12). A 429 is the Auth server's own throttling, which is about the
 * service, not about the credentials; `isUpstreamUnavailable` catches it first (503).
 */
function refusesCredentials(error: unknown): boolean {
  const status = (error as { status?: unknown } | null)?.status;
  return (
    typeof status === 'number' &&
    status >= CLIENT_ERROR_MIN_STATUS &&
    status <= CLIENT_ERROR_MAX_STATUS &&
    status !== TOO_MANY_REQUESTS_STATUS
  );
}

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
        if (isUpstreamUnavailable(error)) throw upstreamFailure('sign in', error);
        if (refusesCredentials(error)) return err(new InvalidCredentialsError());
        throw upstreamFailure('sign in', error);
      }
      // A successful sign-in always carries a session; without one nothing was opened.
      if (data.session === null) throw new Error('sign in returned no session');
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
