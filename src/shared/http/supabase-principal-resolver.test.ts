import { NextRequest } from 'next/server';
import { describe, expect, it, vi } from 'vitest';
import type { KnownKid } from '@/shared/db/needs-auth-server';
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
    knownKids?: Map<string, KnownKid>;
    /** Calls to Auth the (fake) client makes inside `getClaims()`, as measured at its fetch. */
    authCallsInGetClaims?: number;
    /** Runs inside `getClaims()`, before it answers: simulates the library writing cookies. */
    inGetClaims?: (cookies: ReturnType<typeof createCookieJar>) => void;
  } = {},
) {
  const initialCookies = options.cookies ?? SESSION_COOKIES;
  const cookies = createCookieJar(initialCookies);
  const measured = { calls: 0 };
  const getClaims = vi.fn(() => {
    measured.calls += options.authCallsInGetClaims ?? 0;
    if (dropsSession) {
      for (const { name } of initialCookies) cookies.delete(name);
    }
    options.inGetClaims?.(cookies);
    if (claims === 'never-answers') return new Promise<never>(() => undefined);
    return claims instanceof Error ? Promise.reject(claims) : Promise.resolve(claims);
  });
  const supabase = { auth: { getClaims } } as unknown as RequestSupabase;
  const readPrincipal = vi.fn(() =>
    principal instanceof Error ? Promise.reject(principal) : Promise.resolve(principal),
  );
  const logs = createCapturingLogger();
  const request = new NextRequest('http://localhost:3000/api/v1/auth/session', {
    headers: { 'x-real-ip': options.ip ?? '203.0.113.5' },
  });
  const input: ResolvePrincipalInput = {
    request,
    cookies,
    requestId: 'unit-test-request-1',
    logger: logs.logger,
  };
  const fence = vi.fn();
  const resolver = createSupabasePrincipalResolver({
    rateLimiter: options.limiter ?? createInMemoryRateLimiter(),
    requireClientIp: false,
    fingerprint: (subject) => `fingerprint-of-${subject.length}-chars`,
    clientFor: () => supabase,
    readPrincipal,
    deadlineMs: 20,
    authCalls: () => measured.calls,
    fence,
    ...(options.knownKids === undefined ? {} : { knownKids: options.knownKids }),
  });
  return {
    resolver,
    input,
    cookies,
    getClaims,
    readPrincipal,
    supabase,
    logs,
    initialCookies,
    fence,
    request,
  };
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

// A well-formed JWT shape (base64url parts, a future `exp`); the signature is not valid.
const jwt = (header: Record<string, unknown>) =>
  `${b64url(header)}.${b64url({ sub: 'x', exp: NOW_S + HOUR_S })}.${'A'.repeat(43)}`;
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

  it('spends nothing when it is sure no call to Auth would happen: no cookie, an unexpired non-JWT', async () => {
    const { limiter, calls } = recordingLimiter();
    for (const cookies of [[], sessionCookie('not-a-jwt', NOW_S + HOUR_S)]) {
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
      knownKids: new Map([['key-9', { alg: 'ES256', learnedAtMs: Date.now() }]]),
    });
    await knownRun.resolver.resolve(knownRun.input);
    expect(known.calls).toEqual([]);

    const unknown = recordingLimiter();
    const unknownRun = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter: unknown.limiter,
      cookies: asymmetric,
      knownKids: new Map(),
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

// ---------------------------------------------------------- the invariant, in layers ----

const knownEs256 = (): Map<string, KnownKid> =>
  new Map([['key-1', { alg: 'ES256', learnedAtMs: Date.now() }]]);
/** A token a locally known key would verify (the signature is not real: nothing checks it here). */
const localToken = () => jwt({ alg: 'ES256', kid: 'key-1', typ: 'JWT' });
const localCookies = () => sessionCookie(localToken(), NOW_S + HOUR_S);
const claimsFor = (kid: string, alg = 'ES256') => ({
  data: { claims: { sub: PRINCIPAL.userId }, header: { alg, kid } },
  error: null,
});
const SIGNATURE = 'A'.repeat(43);

describe('createSupabasePrincipalResolver: refusing what the library would crash on (F-01)', () => {
  it.each([
    ['an unsupported algorithm with a public kid', jwt({ alg: 'ES384', kid: 'key-1' })],
    ['an algorithm that is a number', jwt({ alg: 5, kid: 'key-1' })],
    ['a known kid asked for another algorithm', jwt({ alg: 'RS256', kid: 'key-1' })],
    ['a header that is not JSON', `bm9wZQ.${b64url({ exp: NOW_S + HOUR_S })}.${SIGNATURE}`],
    [
      'a token without an exp',
      `${b64url({ alg: 'ES256', kid: 'key-1' })}.${b64url({})}.${SIGNATURE}`,
    ],
  ])('401 without a client, a budget unit or a call for %s', async (_label, token) => {
    const { limiter, calls } = recordingLimiter();
    const { resolver, input, getClaims, readPrincipal, initialCookies, cookies } = setup(
      VALID_CLAIMS,
      PRINCIPAL,
      false,
      { limiter, cookies: sessionCookie(token, NOW_S + HOUR_S), knownKids: knownEs256() },
    );

    await expect(resolver.resolve(input)).resolves.toBeNull();

    // refused locally: no budget spent, no call to Auth, nothing read, the cookie untouched
    expect(calls).toEqual([]);
    expect(getClaims).not.toHaveBeenCalled();
    expect(readPrincipal).not.toHaveBeenCalled();
    expect(cookies.getAll()).toEqual(initialCookies);
  });

  it('refuses an access token that is not a string', async () => {
    const cookie = [
      {
        name: '__Host-rt-session',
        value: `base64-${b64url({ access_token: 5, refresh_token: 'r', expires_at: NOW_S + HOUR_S })}`,
      },
    ];
    const { resolver, input, getClaims } = setup(VALID_CLAIMS, PRINCIPAL, false, {
      cookies: cookie,
      knownKids: knownEs256(),
    });
    await expect(resolver.resolve(input)).resolves.toBeNull();
    expect(getClaims).not.toHaveBeenCalled();
  });

  it.each(['DataError', 'NotSupportedError'])(
    'a %s from the key import (a token that asks a key for an algorithm it cannot verify) is a 401, and the kid is kept',
    async (name) => {
      const kids = knownEs256();
      const { resolver, input, fence, logs } = setup(
        new DOMException('the key cannot verify that algorithm', name),
        PRINCIPAL,
        false,
        { cookies: localCookies(), knownKids: kids },
      );

      await expect(resolver.resolve(input)).resolves.toBeNull();

      expect(kids.has('key-1')).toBe(true);
      expect(fence).not.toHaveBeenCalled();
      // logged, so a misconfigured project key (everyone gets 401) is told apart from forgeries
      expect(logs.events('auth.session_key_rejected')).toEqual([
        expect.objectContaining({ level: 'warn', errorName: name }),
      ]);
    },
  );

  it('any other DOMException is NOT a verdict about the token: it is still a failure', async () => {
    const { resolver, input } = setup(
      new DOMException('aborted', 'OperationError'),
      PRINCIPAL,
      false,
      {
        cookies: localCookies(),
        knownKids: knownEs256(),
      },
    );
    await expect(resolver.resolve(input)).rejects.toThrow('verify the session failed unexpectedly');
  });

  it('does NOT turn an unexpected exception of the library into a 401: it is still denied as a failure', async () => {
    const { resolver, input } = setup(new TypeError('boom'), PRINCIPAL, false, {
      cookies: localCookies(),
      knownKids: knownEs256(),
    });
    await expect(resolver.resolve(input)).rejects.toThrow('verify the session failed unexpectedly');
  });
});

describe('createSupabasePrincipalResolver: a request predicted to make no call looks at the limiter memory (F-01)', () => {
  it('is refused (401, no call to Auth) while the limiter already knows its IP to be over budget', async () => {
    const peeks: RateLimitKey[] = [];
    const limiter: RateLimiter = {
      consume: () => Promise.resolve({ allowed: true }),
      peekDenial: (key) => {
        peeks.push(key);
        return { retryAfterSeconds: 60 };
      },
    };
    const { resolver, input, getClaims } = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter,
      cookies: localCookies(),
      knownKids: knownEs256(),
      ip: '203.0.113.50',
    });

    await expect(resolver.resolve(input)).resolves.toBeNull();

    expect(getClaims).not.toHaveBeenCalled();
    expect(peeks).toHaveLength(1);
    expect(peeks[0]).toMatchObject({
      scope: 'ip',
      group: 'session-upstream',
      subject: '203.0.113.50',
    });
  });

  it('is served normally when the IP is not known to be over budget, and spends nothing', async () => {
    const consume = vi.fn(() => Promise.resolve({ allowed: true } as const));
    const limiter: RateLimiter = { consume, peekDenial: () => undefined };
    const { resolver, input, getClaims } = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter,
      cookies: localCookies(),
      knownKids: knownEs256(),
    });

    await expect(resolver.resolve(input)).resolves.toEqual(PRINCIPAL);

    expect(getClaims).toHaveBeenCalledOnce();
    expect(consume).not.toHaveBeenCalled();
  });

  it('works with a limiter that has no memory to look at', async () => {
    const { limiter } = recordingLimiter();
    const { resolver, input } = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter,
      cookies: localCookies(),
      knownKids: knownEs256(),
    });
    await expect(resolver.resolve(input)).resolves.toEqual(PRINCIPAL);
  });

  it('end to end with the in-memory limiter: once forged cookies exhaust an IP, a "local" shape from it is refused too', async () => {
    const limiter = createInMemoryRateLimiter();
    const ip = '203.0.113.60';
    for (let n = 0; n < 61; n += 1) {
      const forged = setup(VALID_CLAIMS, PRINCIPAL, false, { limiter, cookies: FORGED, ip });
      await forged.resolver.resolve(forged.input);
    }

    const local = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter,
      cookies: localCookies(),
      knownKids: knownEs256(),
      ip,
    });
    await expect(local.resolver.resolve(local.input)).resolves.toBeNull();
    expect(local.getClaims).not.toHaveBeenCalled();
  });
});

describe('createSupabasePrincipalResolver: the measurement backstop (F-01)', () => {
  it('a call to Auth that the prediction missed is charged afterwards, and logged without the cookie', async () => {
    const { limiter, calls } = recordingLimiter();
    const { resolver, input, logs } = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter,
      cookies: localCookies(),
      knownKids: knownEs256(),
      authCallsInGetClaims: 1, // the library went to Auth although the prediction said it would not
      ip: '203.0.113.77',
    });

    await resolver.resolve(input);

    expect(calls).toHaveLength(1);
    expect(calls.map(({ key }) => key)).toEqual([
      expect.objectContaining({ group: 'session-upstream', subject: '203.0.113.77' }),
    ]);
    expect(logs.events('auth.session_budget_mispredicted')).toEqual([
      expect.objectContaining({ level: 'warn', calls: 1, ipHash: 'fingerprint-of-12-chars' }),
    ]);
    // the log carries the hash of the IP and the count: never the IP or the cookie
    const everything = logs.lines.join('\n');
    expect(everything).not.toContain('203.0.113.77');
    expect(everything).not.toContain('base64-');
  });

  it('charges as many units as the calls it saw: a refresh that also fetched the keys is charged twice', async () => {
    const { limiter, calls } = recordingLimiter();
    const { resolver, input, logs } = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter,
      cookies: FORGED,
      authCallsInGetClaims: 2,
    });

    await resolver.resolve(input);

    // one unit upfront (predicted) and one afterwards for the second call, which is logged
    expect(calls).toHaveLength(2);
    expect(logs.events('auth.session_budget_mispredicted')).toEqual([
      expect.objectContaining({ calls: 2, charged: 1 }),
    ]);
  });

  it('charges nothing extra when the calls match what was charged, or when no call was made', async () => {
    const one = recordingLimiter();
    const predicted = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter: one.limiter,
      cookies: FORGED,
      authCallsInGetClaims: 1,
    });
    await predicted.resolver.resolve(predicted.input);
    expect(one.calls).toHaveLength(1);

    const none = recordingLimiter();
    const local = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter: none.limiter,
      cookies: localCookies(),
      knownKids: knownEs256(),
      authCallsInGetClaims: 0,
    });
    await local.resolver.resolve(local.input);
    expect(none.calls).toEqual([]);
  });

  it('stops charging at the first refusal: the IP is over budget and the limiter remembers it', async () => {
    let consumed = 0;
    const limiter: RateLimiter = {
      consume: () => {
        consumed += 1;
        return Promise.resolve(
          consumed === 1 ? { allowed: true } : { allowed: false, retryAfterSeconds: 9 },
        );
      },
    };
    const { resolver, input } = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter,
      cookies: FORGED,
      authCallsInGetClaims: 5,
    });

    // the answer of this request does not change: the calls were already made
    await expect(resolver.resolve(input)).resolves.toEqual(PRINCIPAL);
    expect(consumed).toBe(2);
  });

  it('a limiter that fails while charging after the fact is a 503 (fail closed)', async () => {
    const limiter: RateLimiter = { consume: () => Promise.reject(new Error('down')) };
    const { resolver, input } = setup(VALID_CLAIMS, PRINCIPAL, false, {
      limiter,
      cookies: localCookies(),
      knownKids: knownEs256(),
      authCallsInGetClaims: 1,
    });
    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});

describe('createSupabasePrincipalResolver: which signing keys it keeps (F-01)', () => {
  const failing = (name: string, status: number) => ({ data: null, error: { name, status } });

  it('keeps a known kid when the token only fails the LOCAL signature check (an invalid JWT, no call)', async () => {
    const kids = knownEs256();
    const { resolver, input } = setup(failing('AuthInvalidJwtError', 400), PRINCIPAL, false, {
      cookies: localCookies(),
      knownKids: kids,
    });

    await expect(resolver.resolve(input)).resolves.toBeNull();

    // a forger carrying a real kid cannot evict it and make real users pay
    expect(kids.has('key-1')).toBe(true);
  });

  it('forgets it when the failure came after a call to Auth (the JWKS or getUser path ran)', async () => {
    const kids = knownEs256();
    const { resolver, input } = setup(failing('AuthInvalidJwtError', 400), PRINCIPAL, false, {
      cookies: localCookies(),
      knownKids: kids,
      authCallsInGetClaims: 1,
    });

    await resolver.resolve(input);

    expect(kids.has('key-1')).toBe(false);
  });

  it.each([
    ['a plain exception', new TypeError('boom')],
    ['an auth error that is not an invalid JWT', failing('AuthApiError', 401)],
    ['an outage', failing('AuthRetryableFetchError', 0)],
  ])(
    'forgets it when the failure is %s: anything other than an invalid JWT',
    async (_label, claims) => {
      const kids = knownEs256();
      const { resolver, input } = setup(claims, PRINCIPAL, false, {
        cookies: localCookies(),
        knownKids: kids,
      });

      await resolver.resolve(input).catch(() => undefined);

      expect(kids.has('key-1')).toBe(false);
    },
  );

  it('keeps every other kid when it forgets one, and a token that verifies renews its kid', async () => {
    const kids = new Map<string, KnownKid>([
      ['key-1', { alg: 'ES256', learnedAtMs: 1 }],
      ['key-2', { alg: 'ES256', learnedAtMs: 1 }],
    ]);
    // `learnedAtMs: 1` is stale, so the request is charged; it verifies and renews the entry
    const ok = setup(claimsFor('key-1'), PRINCIPAL, false, {
      cookies: localCookies(),
      knownKids: kids,
    });
    await ok.resolver.resolve(ok.input);
    expect(kids.get('key-1')?.learnedAtMs).toBeGreaterThan(1);
    expect(kids.get('key-2')?.learnedAtMs).toBe(1);
  });

  it('remembers the algorithm a kid verified, and bounds how many kids it keeps', async () => {
    const kids = new Map<string, KnownKid>();
    for (let n = 0; n < 20; n += 1) {
      const run = setup(claimsFor(`kid-${n}`, 'RS256'), PRINCIPAL, false, {
        cookies: sessionCookie(jwt({ alg: 'RS256', kid: `kid-${n}` }), NOW_S + HOUR_S),
        knownKids: kids,
      });
      await run.resolver.resolve(run.input);
    }
    expect(kids.size).toBe(16);
    expect(kids.has('kid-0')).toBe(false); // the oldest went first
    expect(kids.get('kid-19')?.alg).toBe('RS256');
  });
});

describe('createSupabasePrincipalResolver: a failure after a refresh keeps the rotated session', () => {
  const rotate = (jar: ReturnType<typeof createCookieJar>) => {
    // what ssr does after a refresh that worked: new values, and a stale chunk deleted
    jar.set('__Host-rt-session.0', 'rotated-chunk-0');
    jar.delete('__Host-rt-session.1');
  };
  const outage = { data: null, error: { name: 'AuthRetryableFetchError', status: 0 } };

  it('refresh OK and the verification then 503: the NEW cookies stay, the consumed refresh token is not put back', async () => {
    const { resolver, input, cookies, fence } = setup(outage, PRINCIPAL, false, {
      inGetClaims: rotate,
    });

    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);

    expect(cookies.getAll()).toEqual([{ name: '__Host-rt-session.0', value: 'rotated-chunk-0' }]);
    expect(fence).toHaveBeenCalledWith(input.request);
  });

  it('the same goes for a deadline that expires after the refresh wrote the new cookies', async () => {
    const { resolver, input, cookies } = setup('never-answers', PRINCIPAL, false, {
      inGetClaims: rotate,
    });

    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);

    expect(cookies.get('__Host-rt-session.0')).toBe('rotated-chunk-0');
    expect(cookies.get('__Host-rt-session.1')).toBeUndefined();
  });

  it('a session that was only REMOVED (the refresh failed) is put back whole', async () => {
    const { resolver, input, cookies, initialCookies, fence } = setup(outage, PRINCIPAL, true);

    await expect(resolver.resolve(input)).rejects.toBeInstanceOf(ServiceUnavailableError);

    expect(cookies.getAll()).toEqual(initialCookies);
    expect(fence).toHaveBeenCalledOnce();
  });

  it('does not fence the client when the request succeeds: the handler still writes through it', async () => {
    const { resolver, input, fence } = setup(VALID_CLAIMS);
    await resolver.resolve(input);
    expect(fence).not.toHaveBeenCalled();
  });

  it('does not fence it on a plain 401 either', async () => {
    const { resolver, input, fence } = setup({
      data: null,
      error: { name: 'AuthApiError', status: 400 },
    });
    await expect(resolver.resolve(input)).resolves.toBeNull();
    expect(fence).not.toHaveBeenCalled();
  });
});
