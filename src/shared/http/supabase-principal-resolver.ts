import { readCurrentPrincipal } from '@/shared/db/current-principal';
import { withDeadline } from '@/shared/db/deadline';
import { getRequestSupabase, type RequestSupabase } from '@/shared/db/server-client';
import { restoreSessionCookies, snapshotSessionCookies } from '@/shared/db/session-cookies';
import { isUpstreamUnavailable, upstreamFailure } from '@/shared/db/upstream-errors';
import { ServiceUnavailableError } from '@/shared/kernel';
import type { PrincipalResolver, ResolvePrincipalInput } from './principal-resolver';

export type SupabasePrincipalResolverOptions = {
  /** Default: the request-scoped client, shared with the handler. Injected by unit tests. */
  readonly clientFor?: (input: ResolvePrincipalInput) => RequestSupabase;
  /** Default: `current_principal()`. Injected by unit tests. */
  readonly readPrincipal?: typeof readCurrentPrincipal;
  /** Bound on the whole `getClaims()` call. Default 5 s (E-21). Shortened by unit tests. */
  readonly deadlineMs?: number;
};

/**
 * Authentication, step 5 of the pipeline (spec §3.3, §3.4):
 *
 * 1. `auth.getClaims()` on the request's client. It reads the session from the cookie, renews an
 *    expired access token with the refresh token (the new cookies go through the pipeline's jar
 *    into the response, errors included) and verifies the access token: against the project's
 *    signing keys (JWKS) when they are asymmetric (SEC-20), or through the Auth server's `getUser`
 *    with the legacy symmetric secret, as in the local stack. `getSession()` is never used: it
 *    trusts the cookie without verifying it (SEC-07).
 * 2. `current_principal()`: the database accepts the session only while its `auth.sessions` row
 *    exists and the profile is not disabled, so logout and deactivation take effect on the next
 *    request even though the JWT is still valid (E-08). Role and tenant come from `profiles`,
 *    never from the token.
 *
 * No session, an invalid or revoked one, or no principal → `null` (401). Supabase slow or down →
 * `ServiceUnavailableError` (503, E-21). Anything unexpected throws and denies (500).
 */
export function createSupabasePrincipalResolver(
  options: SupabasePrincipalResolverOptions = {},
): PrincipalResolver {
  const clientFor =
    options.clientFor ??
    ((input: ResolvePrincipalInput) =>
      getRequestSupabase({
        request: input.request,
        cookies: input.cookies,
        requestId: input.requestId,
      }));
  const readPrincipal = options.readPrincipal ?? readCurrentPrincipal;

  return {
    async resolve(input) {
      const supabase = clientFor(input);

      // When the Auth server cannot answer (down, slow, throttling us), the client library may
      // already have dropped the session from the jar while it tried to refresh it. A transient
      // failure must not log the user out, so the cookies are put back before the 503.
      const sessionBefore = snapshotSessionCookies(input.cookies);
      const unavailable = (cause: unknown): Error => {
        restoreSessionCookies(input.cookies, sessionBefore);
        return cause instanceof ServiceUnavailableError
          ? cause
          : upstreamFailure('verify the session', cause);
      };

      let result: Awaited<ReturnType<typeof supabase.auth.getClaims>>;
      try {
        // The refresh inside getClaims() retries with backoff for up to 30 s on its own: bound the
        // whole call, not only each request.
        result = await withDeadline(
          'verify the session',
          supabase.auth.getClaims(),
          options.deadlineMs,
        );
      } catch (cause) {
        throw unavailable(cause);
      }

      const { data, error } = result;
      if (error) {
        // A verdict about the token (missing, expired beyond refresh, revoked, forged) is a 401;
        // a failure of the Auth server is a 503.
        if (isUpstreamUnavailable(error)) throw unavailable(error);
        return null;
      }
      if (data === null || typeof data.claims.sub !== 'string' || data.claims.sub === '') {
        return null;
      }

      return await readPrincipal(supabase);
    },
  };
}
