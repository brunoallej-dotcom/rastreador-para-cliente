import { readCurrentPrincipal } from '@/shared/db/current-principal';
import { withDeadline } from '@/shared/db/deadline';
import { needsAuthServer } from '@/shared/db/needs-auth-server';
import { getRequestSupabase, type RequestSupabase } from '@/shared/db/server-client';
import { restoreSessionCookies, snapshotSessionCookies } from '@/shared/db/session-cookies';
import { isUpstreamUnavailable, upstreamFailure } from '@/shared/db/upstream-errors';
import { ServiceUnavailableError } from '@/shared/kernel';
import { resolveIpSubject } from './client-ip';
import { RateLimitedError } from './pipeline-errors';
import type { PrincipalResolver, ResolvePrincipalInput } from './principal-resolver';
import { enforceRateLimits } from './rate-limit/enforce';
import type { RateLimiter, RateLimitRule } from './rate-limit/rate-limiter';

/**
 * The per-IP budget of requests whose session cookie would make the server call the Auth server
 * (see `needsAuthServer`): 60 per 15 minutes per client IP (IPv6 aggregated to its /64).
 *
 * Why it exists (F-01): the Auth server sees only the server's IP, so it throttles ALL users
 * together once a few clients make it answer 429. A forged cookie (`expires_at: 1` is enough) makes
 * every authenticated GET cause a call to Auth, and nothing limits it before authentication. The
 * budget caps what ONE client can cause, far below the quota of Auth.
 *
 * Why 60 per 15 minutes: a real browser uses it once per access-token life (15 min) when the token
 * is refreshed, and never when the project signs with asymmetric keys (SEC-20: the token is verified
 * locally); 60 leaves room for many people behind one office address, and a forger gets a minute
 * of calls and then 401s. A project still on the legacy symmetric JWT secret would spend it on EVERY
 * request (its tokens are checked by the Auth server): SEC-20 requires asymmetric keys, which the
 * local stack uses too (ES256 with a JWKS).
 */
export const SESSION_UPSTREAM_RULE = {
  scope: 'ip',
  group: 'session-upstream',
  limit: 60,
  windowSeconds: 900,
} as const satisfies RateLimitRule;

/** `kid`s that have verified a token in this process; a bounded set. */
const MAX_KNOWN_KIDS = 16;
const verifiedKids = new Set<string>();

function rememberKid(kid: unknown): void {
  if (typeof kid !== 'string' || kid === '' || verifiedKids.has(kid)) return;
  if (verifiedKids.size >= MAX_KNOWN_KIDS) verifiedKids.clear();
  verifiedKids.add(kid);
}

export type SupabasePrincipalResolverOptions = {
  /** The limiter that holds the `session-upstream` budget: the pipeline's own. */
  readonly rateLimiter: RateLimiter;
  /** Production: refuse (503) a request that arrives without a client IP. */
  readonly requireClientIp: boolean;
  /** Keyed fingerprint of a subject, for the `auth.rate_limited` log (never the subject). */
  readonly fingerprint: (subject: string) => string;
  /** Default: the request-scoped client, shared with the handler. Injected by unit tests. */
  readonly clientFor?: (input: ResolvePrincipalInput) => RequestSupabase;
  /** Default: `current_principal()`. Injected by unit tests. */
  readonly readPrincipal?: typeof readCurrentPrincipal;
  /** Bound on the whole `getClaims()` call. Default 5 s (E-21). Shortened by unit tests. */
  readonly deadlineMs?: number;
  /** Milliseconds since the epoch. Default `Date.now`. */
  readonly now?: () => number;
  /** `kid`s known to verify locally. Default: the ones this process has seen verify a token. */
  readonly knownKids?: ReadonlySet<string>;
};

/**
 * Authentication, step 5 of the pipeline (spec §3.3, §3.4):
 *
 * 0. If the session cookie would make the server call the Auth server (an expired token to refresh,
 *    or one it cannot verify locally), the client IP spends the `session-upstream` budget first.
 *    Over budget the answer is `null` (401) and the cookies are left alone: nothing is deleted, so
 *    a legitimate browser behind a busy address keeps its session and simply tries again. A
 *    limiter that fails denies with 503 (fail closed).
 * 1. `auth.getClaims()` on the request's client. It reads the session from the cookie, renews an
 *    expired access token with the refresh token (the new cookies go through the pipeline's jar
 *    into the response, errors included) and verifies the access token: against the project's
 *    signing keys (JWKS) when they are asymmetric (SEC-20), or through the Auth server's `getUser`
 *    with a legacy symmetric secret. `getSession()` is never used: it
 *    trusts the cookie without verifying it (SEC-07).
 * 2. `current_principal()`: the database accepts the session only while its `auth.sessions` row
 *    exists, within its time limits, and the profile is not disabled, so logout and deactivation
 *    take effect on the next request even though the JWT is still valid (E-08). Role and tenant
 *    come from `profiles`, never from the token.
 *
 * No session, an invalid or revoked one, or no principal → `null` (401). Supabase slow or down →
 * `ServiceUnavailableError` (503, E-21). Anything unexpected throws and denies (500).
 */
export function createSupabasePrincipalResolver(
  options: SupabasePrincipalResolverOptions,
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
  const now = options.now ?? Date.now;
  const knownKids = options.knownKids ?? verifiedKids;

  return {
    async resolve(input) {
      // When the Auth server cannot answer (down, slow, throttling us), the client library may
      // already have dropped the session from the jar while it tried to refresh it. A transient
      // failure must not log the user out, so the cookies are put back before the 503.
      const sessionBefore = snapshotSessionCookies(input.cookies);

      if (needsAuthServer(sessionBefore, now(), knownKids)) {
        try {
          await enforceRateLimits({
            limiter: options.rateLimiter,
            rules: [SESSION_UPSTREAM_RULE],
            scope: 'ip',
            subject: resolveIpSubject(input.request, options.requireClientIp),
            logger: input.logger,
            fingerprint: options.fingerprint,
          });
        } catch (error) {
          // Over budget: 401 without touching the cookies (and without calling Auth).
          if (error instanceof RateLimitedError) return null;
          throw error;
        }
      }

      const supabase = clientFor(input);
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
      // A signature the project's own key verified: from now on this `kid` is checked locally.
      if (typeof data.header.alg === 'string' && !data.header.alg.startsWith('HS')) {
        rememberKid(data.header.kid);
      }

      return await readPrincipal(supabase);
    },
  };
}
