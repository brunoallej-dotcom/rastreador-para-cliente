import { NextRequest } from 'next/server';
import { describe, expect, it, vi } from 'vitest';
import type { RequestSupabase } from '@/shared/db/server-client';
import { ServiceUnavailableError, type Principal } from '@/shared/kernel';
import { createCookieJar } from './cookies';
import type { ResolvePrincipalInput } from './principal-resolver';
import { createInMemoryRateLimiter } from './rate-limit/in-memory-rate-limiter';
import type { RateLimitKey, RateLimiter, RateLimitRule } from './rate-limit/rate-limiter';
import {
  createSupabasePrincipalResolver,
  SESSION_UPSTREAM_RULE,
} from './supabase-principal-resolver';
import { createCapturingLogger } from './testing';

const PRINCIPAL: Principal = {
  userId: '11111111-1111-4111-8111-111111111111',
  role: 'client',
  clientId: '22222222-2222-4222-8222-222222222222',
  displayName: 'Maria',
  aal: 'aal1',
  pendingActions: [],
};

type ClaimsOutcome = { data: unknown; error: unknown } | Error | 'never-answers';

const SESSION_COOKIES = [
  { name: '__Host-rt-session.0', value: 'chunk-0' },
  { name: '__Host-rt-session.1', value: 'chunk-1' },
];

/**
 * `dropsSession`: `getClaims()` deletes the session cookies from the jar before it answers, like the
 * client library does when a token refresh fails.
 */
function setup(
  claims: ClaimsOutcome,
  principal: Principal | null | Error = PRINCIPAL,
  dropsSession = false,
  options: {
    limiter?: RateLimiter;
    cookies?: { name: string; value: string }[];
    ip?: string;
    knownKids?: ReadonlySet<string>;
  } = {},
) {
  const initialCookies = options.cookies ?? SESSION_COOKIES;
  const cookies = createCookieJar(initialCookies);
  const getClaims = vi.fn(() => {
    if (dropsSession) {
      for (const { name } of initialCookies) cookies.delete(name);
    }
    if (claims === 'never-answers') return new Promise<never>(() => undefined);
    return claims instanceof Error ? Promise.reject(claims) : Promise.resolve(claims);
  });
  const supabase = { auth: { getClaims } } as unknown as RequestSupabase;
  const readPrincipal = vi.fn(() =>
    principal instanceof Error ? Promise.reject(principal) : Promise.resolve(principal),
  );
  const logs = createCapturingLogger();
  const input: ResolvePrincipalInput = {
    request: new NextRequest('http://localhost:3000/api/v1/auth/session', {
      headers: { 'x-real-ip': options.ip ?? '203.0.113.5' },
    }),
    cookies,
    requestId: 'unit-test-request-1',
    logger: logs.logger,
  };
  const resolver = createSupabasePrincipalResolver({
    rateLimiter: options.limiter ?? createInMemoryRateLimiter(),
    requireClientIp: false,
    fingerprint: (subject) => `fingerprint-of-${subject.length}-chars`,
    clientFor: () => supabase,
    readPrincipal,
    deadlineMs: 20,
    ...(options.knownKids === undefined ? {} : { knownKids: options.knownKids }),
  });
  return { resolver, input, cookies, getClaims, readPrincipal, supabase, logs, initialCookies };
}

const VALID_CLAIMS = {
  data: { claims: { sub: PRINCIPAL.userId }, header: { alg: 'ES256', kid: 'unit-test-key' } },
  error: null,
};

describe('createSupabasePrincipalResolver', () => {
  it('SEC-07: verifies the token with getClaims() and then loads the principal from the database', async () => {
    const { resolver, input, getClaims, readPrincipal, supabase } = setup(VALID_CLAIMS);

    await expect(resolver.resolve(input)).resolves.toEqual(PRINCIPAL);

    expect(getClaims).toHaveBeenCalledOnce();
    expect(readPrincipal).toHaveBeenCalledOnce();
    expect(readPrincipal).toHaveBeenCalledWith(supabase);
  });

  it('is unauthenticated, without touching the database, when there is no session', async () => {
    const { resolver, input, readPrincipal } = setup({ data: null, error: null });
    await expect(resolver.resolve(input)).resolves.toBeNull();
    expect(readPrincipal).not.toHaveBeenCalled();
  });

  it.each([
    ['an invalid JWT', { name: 'AuthInvalidJwtError', status: 401 }],
    ['a revoked session', { name: 'AuthApiError', status: 403, code: 'session_not_found' }],
    ['a refresh token that was already used', { name: 'AuthApiError', status: 400 }],
    ['a missing session', { name: 'AuthSessionMissingError', status: 400 }],
  ])('is unauthenticated on %s', async (_label, error) => {
    const { resolver, input, readPrincipal } = setup({ data: null, error });
    await expect(resolver.resolve(input)).resolves.toBeNull();
    expect(readPrincipal).not.toHaveBeenCalled();
  });

  it('is unauthenticated when the claims carry no subject', async () => {
    const { resolver, input } = setup({ data: { claims: {} }, error: null });
    await expect(resolver.resolve(input)).resolves.toBeNull();
  });

  it('E-08: is unauthenticated when the database finds no principal (revoked session, disabled profile)', async () => {
    const { resolver, input } = setup(VALID_CLAIMS, null);
    await expect(resolver.resolve(input)).resolves.toBeNull();
  });

  it('E-21: the Auth server being down is ServiceUnavailableError, not a 401', async () => {
    const { resolver, input, readPrincipal } = setup({
      data: null,
      error: { name: 'AuthRetryableFetchError', status: 0 },
    });
    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);
    expect(readPrincipal).not.toHaveBeenCalled();
  });

  it('E-21: Auth throttling a token refresh (429) is a 503 and keeps the session cookies', async () => {
    const { resolver, input, cookies } = setup(
      { data: null, error: { name: 'AuthApiError', status: 429, code: 'over_request_rate_limit' } },
      PRINCIPAL,
      true,
    );

    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);

    expect(cookies.getAll()).toEqual(SESSION_COOKIES);
  });

  it('E-21: a getClaims() that never answers is a 503 within the deadline, cookies kept', async () => {
    const { resolver, input, cookies } = setup('never-answers', PRINCIPAL, true);

    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);

    expect(cookies.getAll()).toEqual(SESSION_COOKIES);
  });

  it('a genuine "this session is dead" verdict is a 401 and does NOT restore the cookies', async () => {
    const { resolver, input, cookies } = setup(
      { data: null, error: { name: 'AuthApiError', status: 400, code: 'refresh_token_not_found' } },
      PRINCIPAL,
      true,
    );

    await expect(resolver.resolve(input)).resolves.toBeNull();

    expect(cookies.getAll()).toEqual([]);
  });

  it('E-21: a thrown timeout is ServiceUnavailableError too', async () => {
    const { resolver, input } = setup(new DOMException('timed out', 'TimeoutError'));
    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('denies (500) on an unexpected throw instead of resolving a principal', async () => {
    const { resolver, input } = setup(new Error('boom'));
    const rejection = resolver.resolve(input);
    await expect(rejection).rejects.toThrow('verify the session failed unexpectedly');
    await expect(rejection).rejects.not.toBeInstanceOf(ServiceUnavailableError);
  });

  it('passes through what the database read throws (503 or 500)', async () => {
    const { resolver, input } = setup(VALID_CLAIMS, new ServiceUnavailableError('db down'));
    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});

// -------------------------------------------------------------------------------------- F-01 ----

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
const NOW_S = Math.floor(Date.now() / 1000);
const HOUR_S = 3600;

const jwt = (header: Record<string, unknown>) =>
  `${b64url(header)}.${b64url({ sub: 'x' })}.signature`;
const sessionCookie = (accessToken: string, expiresAt: number) => [
  {
    name: '__Host-rt-session',
    value: `base64-${b64url({ access_token: accessToken, refresh_token: 'y', expires_at: expiresAt })}`,
  },
];

/** The forged cookie of the finding: it needs no real token, only `expires_at` in the past. */
const FORGED = sessionCookie('x', 1);

/** A limiter that records what it was asked and answers `decide` (allow by default). */
function recordingLimiter(decide: () => 'allow' | 'deny' | 'fail' = () => 'allow') {
  const calls: { key: RateLimitKey; rule: RateLimitRule }[] = [];
  const limiter: RateLimiter = {
    consume(key, rule) {
      calls.push({ key, rule });
      const outcome = decide();
      if (outcome === 'fail') return Promise.reject(new Error('limiter down'));
      return Promise.resolve(
        outcome === 'allow' ? { allowed: true } : { allowed: false, retryAfterSeconds: 300 },
      );
    },
  };
  return { limiter, calls };
}

describe('createSupabasePrincipalResolver: the session-upstream budget (F-01)', () => {
  it('is 60 per 15 minutes per IP, in its own named group', () => {
    expect(SESSION_UPSTREAM_RULE).toEqual({
      scope: 'ip',
      group: 'session-upstream',
      limit: 60,
      windowSeconds: 900,
    });
  });

  it('F-01: a forged cookie that would make the server call Auth spends the budget of its IP first', async () => {
    const { limiter, calls } = recordingLimiter();
    const { resolver, input, getClaims } = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter,
      cookies: FORGED,
      ip: '203.0.113.77',
    });

    await resolver.resolve(input);

    expect(calls).toHaveLength(1);
    expect(calls[0]?.rule).toEqual(SESSION_UPSTREAM_RULE);
    expect(calls[0]?.key).toMatchObject({
      scope: 'ip',
      group: 'session-upstream',
      bucket: 'ip:session-upstream',
      subject: '203.0.113.77',
    });
    expect(getClaims).toHaveBeenCalledOnce();
  });

  it('F-01: over budget it is a 401 (null) with no call to Auth, no principal read and the cookies untouched', async () => {
    const { limiter } = recordingLimiter(() => 'deny');
    const { resolver, input, getClaims, readPrincipal, cookies, initialCookies } = setup(
      VALID_CLAIMS,
      PRINCIPAL,
      false,
      { limiter, cookies: FORGED },
    );

    await expect(resolver.resolve(input)).resolves.toBeNull();

    expect(getClaims).not.toHaveBeenCalled();
    expect(readPrincipal).not.toHaveBeenCalled();
    // nothing was deleted or rewritten: a legitimate browser behind a busy address keeps its session
    expect(cookies.getAll()).toEqual(initialCookies);
    const headers = new Headers();
    cookies.applyTo(headers);
    expect(headers.getSetCookie()).toEqual([]);
  });

  it('F-01: logs auth.rate_limited with the group and the scope, and a hash of the IP, never the IP', async () => {
    const { limiter } = recordingLimiter(() => 'deny');
    const { resolver, input, logs } = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter,
      cookies: FORGED,
      ip: '203.0.113.77',
    });

    await resolver.resolve(input);

    expect(logs.events('auth.rate_limited')).toEqual([
      expect.objectContaining({
        event: 'auth.rate_limited',
        scope: 'ip',
        group: 'session-upstream',
        subjectHash: 'fingerprint-of-12-chars',
      }),
    ]);
    expect(logs.lines.join('\n')).not.toContain('203.0.113.77');
  });

  it('E-22: a limiter that fails is a 503 (fail closed), and Auth is not called', async () => {
    const { limiter } = recordingLimiter(() => 'fail');
    const { resolver, input, getClaims } = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter,
      cookies: FORGED,
    });

    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);
    expect(getClaims).not.toHaveBeenCalled();
  });

  it('F-01: N forged requests from one IP produce at most 60 calls to Auth', async () => {
    const limiter = createInMemoryRateLimiter();
    let authCalls = 0;
    const outcomes: unknown[] = [];
    for (let n = 0; n < 100; n += 1) {
      const { resolver, input, getClaims } = setup(
        {
          data: null,
          error: { name: 'AuthApiError', status: 400, code: 'refresh_token_not_found' },
        },
        PRINCIPAL,
        false,
        { limiter, cookies: FORGED, ip: '203.0.113.200' },
      );
      outcomes.push(await resolver.resolve(input));
      authCalls += getClaims.mock.calls.length;
    }

    expect(authCalls).toBe(60);
    // every request is a 401 either way; only the first 60 reached Auth
    expect(outcomes.every((outcome) => outcome === null)).toBe(true);
  });

  it('F-01: the budget is per IP: another address is not affected by a forger', async () => {
    const limiter = createInMemoryRateLimiter();
    for (let n = 0; n < 61; n += 1) {
      const { resolver, input } = setup(VALID_CLAIMS, PRINCIPAL, false, {
        limiter,
        cookies: FORGED,
        ip: '203.0.113.201',
      });
      await resolver.resolve(input);
    }

    const { resolver, input, getClaims } = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter,
      cookies: FORGED,
      ip: '203.0.113.202',
    });
    await expect(resolver.resolve(input)).resolves.toEqual(PRINCIPAL);
    expect(getClaims).toHaveBeenCalledOnce();
  });

  it('spends nothing when no call to Auth would happen: no cookie, a malformed one, an unexpired non-JWT', async () => {
    const { limiter, calls } = recordingLimiter();
    for (const cookies of [
      [],
      [{ name: '__Host-rt-session', value: 'garbage' }],
      sessionCookie('not-a-jwt', NOW_S + HOUR_S),
    ]) {
      const { resolver, input } = setup({ data: null, error: null }, PRINCIPAL, false, {
        limiter,
        cookies,
      });
      await resolver.resolve(input);
    }
    expect(calls).toEqual([]);
  });

  it('spends the budget for a symmetric (HS256) token even when it has not expired', async () => {
    const { limiter, calls } = recordingLimiter();
    const { resolver, input } = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter,
      cookies: sessionCookie(jwt({ alg: 'HS256', typ: 'JWT' }), NOW_S + HOUR_S),
    });

    await resolver.resolve(input);

    expect(calls).toHaveLength(1);
  });

  it('with asymmetric keys a token of a known kid is verified locally and spends nothing; an unknown kid spends', async () => {
    const asymmetric = sessionCookie(jwt({ alg: 'ES256', kid: 'key-9' }), NOW_S + HOUR_S);

    const known = recordingLimiter();
    const knownRun = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter: known.limiter,
      cookies: asymmetric,
      knownKids: new Set(['key-9']),
    });
    await knownRun.resolver.resolve(knownRun.input);
    expect(known.calls).toEqual([]);

    const unknown = recordingLimiter();
    const unknownRun = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter: unknown.limiter,
      cookies: asymmetric,
      knownKids: new Set(),
    });
    await unknownRun.resolver.resolve(unknownRun.input);
    expect(unknown.calls).toHaveLength(1);
  });

  it('learns a kid from a token that verified: the next requests with it are checked locally', async () => {
    const cookies = sessionCookie(jwt({ alg: 'ES256', kid: 'key-learned-1' }), NOW_S + HOUR_S);
    const claims = {
      data: { claims: { sub: PRINCIPAL.userId }, header: { alg: 'ES256', kid: 'key-learned-1' } },
      error: null,
    };
    const { limiter, calls } = recordingLimiter();

    // default known kids: this process's memory
    for (let n = 0; n < 3; n += 1) {
      const { resolver, input } = setup(claims, PRINCIPAL, false, { limiter, cookies });
      await resolver.resolve(input);
    }

    // only the first one (kid unknown) spent the budget
    expect(calls).toHaveLength(1);
  });

  it('does not learn a kid from a symmetric token', async () => {
    const cookies = sessionCookie(jwt({ alg: 'HS256', kid: 'key-hs-1' }), NOW_S + HOUR_S);
    const claims = {
      data: { claims: { sub: PRINCIPAL.userId }, header: { alg: 'HS256', kid: 'key-hs-1' } },
      error: null,
    };
    const { limiter, calls } = recordingLimiter();

    for (let n = 0; n < 3; n += 1) {
      const { resolver, input } = setup(claims, PRINCIPAL, false, { limiter, cookies });
      await resolver.resolve(input);
    }

    expect(calls).toHaveLength(3);
  });
});
