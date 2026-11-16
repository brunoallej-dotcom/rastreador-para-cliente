import type { NextRequest } from 'next/server';
import { readCurrentPrincipal } from '@/shared/db/current-principal';
import { withDeadline } from '@/shared/db/deadline';
import { classifySession, type KnownKid } from '@/shared/db/needs-auth-server';
import {
  fenceRequestClient,
  getRequestAuthCalls,
  getRequestSupabase,
  type RequestSupabase,
} from '@/shared/db/server-client';
import { restoreSessionCookies, snapshotSessionCookies } from '@/shared/db/session-cookies';
import { isUpstreamUnavailable, upstreamFailure } from '@/shared/db/upstream-errors';
import { ServiceUnavailableError } from '@/shared/kernel';
import { clientIp, resolveIpSubject } from './client-ip';
import { RateLimitedError } from './pipeline-errors';
import type { PrincipalResolver, ResolvePrincipalInput } from './principal-resolver';
import { enforceRateLimits } from './rate-limit/enforce';
import { rateLimitBucket } from './rate-limit/group';
import type { RateLimiter, RateLimitKey, RateLimitRule } from './rate-limit/rate-limiter';

/**
 * The per-IP budget of requests whose session cookie would make the server call the Auth server
 * (see `classifySession`): 60 per 15 minutes per client IP (IPv6 aggregated to its /64).
 *
 * Why it exists (F-01): the Auth server sees only the server's IP, so it throttles ALL users
 * together once a few clients make it answer 429. A forged cookie (`expires_at: 1` is enough) makes
 * every authenticated GET cause a call to Auth, and nothing limits it before authentication. The
 * budget caps what ONE client can cause, far below the quota of Auth.
 *
 * The invariant: every call to Auth made while resolving a principal is charged to this budget, and
 * an IP over budget never reaches Auth. It is kept in three layers: a prediction that fails closed
 * (`classifySession`), a peek at the limiter's memory for a request predicted to make no call, and a
 * MEASUREMENT of the calls the client really made, charged after the fact.
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

/** Signing keys that have verified a token in this process; a bounded map, oldest entry out first. */
const MAX_KNOWN_KIDS = 16;
const verifiedKids = new Map<string, KnownKid>();

function learnKid(kids: Map<string, KnownKid>, kid: unknown, alg: unknown, nowMs: number): void {
  if (typeof kid !== 'string' || kid === '' || typeof alg !== 'string') return;
  kids.delete(kid); // re-inserting moves it to the newest position
  if (kids.size >= MAX_KNOWN_KIDS) {
    const oldest = kids.keys().next();
    if (oldest.done !== true) kids.delete(oldest.value);
  }
  kids.set(kid, { alg, learnedAtMs: nowMs });
}

export type SupabasePrincipalResolverOptions = {
  /** The limiter that holds the `session-upstream` budget: the pipeline's own. */
  readonly rateLimiter: RateLimiter;
  /** Production: refuse (503) a request that arrives without a client IP. */
  readonly requireClientIp: boolean;
  /** Keyed fingerprint of a subject, for the log lines (never the subject). */
  readonly fingerprint: (subject: string) => string;
  /** Default: the request-scoped client, shared with the handler. Injected by unit tests. */
  readonly clientFor?: (input: ResolvePrincipalInput) => RequestSupabase;
  /** Default: `current_principal()`. Injected by unit tests. */
  readonly readPrincipal?: typeof readCurrentPrincipal;
  /** Bound on the whole `getClaims()` call. Default 5 s (E-21). Shortened by unit tests. */
  readonly deadlineMs?: number;
  /** Milliseconds since the epoch. Default `Date.now`. */
  readonly now?: () => number;
  /** Signing keys known to verify locally. Default: the ones this process has seen verify a token. */
  readonly knownKids?: Map<string, KnownKid>;
  /** Calls the request's client has made to Auth so far. Default: measured at its fetch. */
  readonly authCalls?: (request: NextRequest) => number;
  /** Stops the request's client from writing cookies. Default: the client's own fence. */
  readonly fence?: (request: NextRequest) => void;
};

/**
 * Authentication, step 5 of the pipeline (spec §3.3, §3.4):
 *
 * 0. The session cookie is read the way the Auth client reads it and classified (see
 *    `classifySession`). A session the client would fail on with an exception that is not an auth
 *    error (a token it cannot decode, an algorithm it does not support) is answered 401 here, so no
 *    anonymous caller can cause a 500. One that may make the server call the Auth server (an expired
 *    token to refresh, or anything the parse cannot rule out) first spends the client IP's
 *    `session-upstream` budget: over budget the answer is `null` (401), the cookies are left alone
 *    and Auth is not called. One that provably verifies locally spends nothing, but is refused too
 *    while its IP is known to be over budget (a second line, from the limiter's memory). A limiter
 *    that fails denies with 503 (fail closed).
 * 1. `auth.getClaims()` on the request's client. It reads the session from the cookie, renews an
 *    expired access token with the refresh token (the new cookies go through the pipeline's jar
 *    into the response, errors included) and verifies the access token: against the project's
 *    signing keys (JWKS) when they are asymmetric (SEC-20), or through the Auth server's `getUser`
 *    with a legacy symmetric secret. `getSession()` is never used: it trusts the cookie without
 *    verifying it (SEC-07). The calls it really makes to Auth are counted at the client's fetch, and
 *    any not charged beforehand are charged afterwards (`auth.session_budget_mispredicted`).
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
  const authCalls = options.authCalls ?? getRequestAuthCalls;
  const fence = options.fence ?? fenceRequestClient;

  const budgetKey = (subject: string): RateLimitKey => ({
    scope: SESSION_UPSTREAM_RULE.scope,
    group: SESSION_UPSTREAM_RULE.group,
    bucket: rateLimitBucket(SESSION_UPSTREAM_RULE),
    subject,
  });

  /** Spends ONE unit of the IP's budget; `false` when the IP is over budget. */
  const spendUnit = async (input: ResolvePrincipalInput, subject: string): Promise<boolean> => {
    try {
      await enforceRateLimits({
        limiter: options.rateLimiter,
        rules: [SESSION_UPSTREAM_RULE],
        scope: 'ip',
        subject,
        logger: input.logger,
        fingerprint: options.fingerprint,
      });
      return true;
    } catch (error) {
      if (error instanceof RateLimitedError) return false;
      throw error;
    }
  };

  return {
    async resolve(input) {
      // When the Auth server cannot answer (down, slow, throttling us), the client library may
      // already have dropped the session from the jar while it tried to refresh it. A transient
      // failure must not log the user out, so a session that was REMOVED is put back before the 503
      // (one that was rewritten by a refresh that did succeed is left as it is).
      const sessionBefore = snapshotSessionCookies(input.cookies);
      const session = await classifySession(sessionBefore, now(), knownKids);

      if (session.kind === 'none') return null; // no session cookie: no call, a 401
      if (session.kind === 'refuse') return null; // would be a 500 inside the library: a 401 here

      let charged = 0;
      let ipSubject: string | undefined;
      if (session.kind === 'upstream') {
        ipSubject = resolveIpSubject(input.request, options.requireClientIp);
        // Over budget: 401, no call to Auth, cookies untouched.
        if (!(await spendUnit(input, ipSubject))) return null;
        charged = 1;
      } else {
        // Predicted local: nothing is spent. But an IP the limiter already knows to be over budget is
        // refused all the same: if the prediction is ever wrong, a forged shape stops reaching Auth
        // as soon as its IP runs out of budget. A peek: no count, no store, no call.
        const ip = clientIp(input.request);
        const denial =
          ip === undefined
            ? undefined
            : options.rateLimiter.peekDenial?.(budgetKey(ip), SESSION_UPSTREAM_RULE);
        if (denial !== undefined) return null;
        ipSubject = ip;
      }

      const supabase = clientFor(input);
      const callsBefore = authCalls(input.request);

      let result: Awaited<ReturnType<typeof supabase.auth.getClaims>> | undefined;
      let failure: unknown;
      let failed = false;
      try {
        // The refresh inside getClaims() retries with backoff for up to 30 s on its own: bound the
        // whole call, not only each request.
        result = await withDeadline(
          'verify the session',
          supabase.auth.getClaims(),
          options.deadlineMs,
        );
      } catch (cause) {
        failed = true;
        failure = cause;
      }

      // The measurement: every call to Auth the client really made is charged. A call that was not
      // charged beforehand means the prediction was wrong; it is charged now and logged.
      const made = authCalls(input.request) - callsBefore;
      if (made > charged) {
        const subject = ipSubject ?? clientIp(input.request) ?? undefined;
        input.logger.warn(
          {
            event: 'auth.session_budget_mispredicted',
            calls: made,
            charged,
            ipHash: subject === undefined ? undefined : options.fingerprint(subject),
          },
          'auth.session_budget_mispredicted',
        );
        if (subject !== undefined) {
          for (let extra = charged; extra < made; extra += 1) {
            // stop at the first refusal: the IP is over budget and the limiter now remembers it
            if (!(await spendUnit(input, subject))) break;
          }
        }
      }

      const unavailable = (cause: unknown): Error => {
        // Stop late writes first, then put a REMOVED session back: the order keeps the decision stable.
        fence(input.request);
        restoreSessionCookies(input.cookies, sessionBefore);
        return cause instanceof ServiceUnavailableError
          ? cause
          : upstreamFailure('verify the session', cause);
      };

      // A token that asks a signing key for an algorithm it cannot verify (RS256 against an EC key)
      // makes WebCrypto reject the key import with a DOMException, which the library does not wrap.
      // It is a verdict about the token, not an outage: 401. Deliberately narrow: only these two
      // error names of that one exception type, so a genuine bug still surfaces as a 500.
      if (failed && isKeyImportRejection(failure)) {
        // Logged: if the project's own key ever started failing this way (a misconfigured key),
        // every user would get 401, and this line is what tells that apart from forged tokens.
        input.logger.warn(
          { event: 'auth.session_key_rejected', errorName: failure.name },
          'auth.session_key_rejected',
        );
        return null;
      }

      if (failed) {
        forgetKidOnFailure(knownKids, session, failure, made);
        throw unavailable(failure);
      }
      if (result === undefined) return null;

      const { data, error } = result;
      if (error) {
        forgetKidOnFailure(knownKids, session, error, made);
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
        learnKid(knownKids, data.header.kid, data.header.alg, now());
      }

      return await readPrincipal(supabase);
    },
  };
}

const KEY_IMPORT_REJECTIONS: ReadonlySet<string> = new Set(['DataError', 'NotSupportedError']);

function isKeyImportRejection(error: unknown): error is DOMException {
  return error instanceof DOMException && KEY_IMPORT_REJECTIONS.has(error.name);
}

/**
 * Forgets a signing key whose token failed in a way that says the key may not be the one the process
 * thinks: the failure came after a call to Auth (the `getUser` or JWKS path ran, so the key was not
 * served from the library's cache), or it was anything other than a plain `AuthInvalidJwtError`.
 * A failure that is only a local signature mismatch (an `AuthInvalidJwtError` with no call to Auth)
 * does NOT forget it: otherwise a forger carrying a real `kid` could evict it over and over and make
 * real users pay a unit each time.
 */
function forgetKidOnFailure(
  kids: Map<string, KnownKid>,
  session: Awaited<ReturnType<typeof classifySession>>,
  failure: unknown,
  authCallsMade: number,
): void {
  const kid = session.kind === 'local' || session.kind === 'upstream' ? session.kid : undefined;
  if (kid === undefined || !kids.has(kid)) return;

  const isLocalSignatureFailure =
    (failure as { name?: unknown } | null)?.name === 'AuthInvalidJwtError' && authCallsMade === 0;
  if (!isLocalSignatureFailure) kids.delete(kid);
}
