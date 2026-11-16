import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import { parse } from 'yaml';
import { z } from 'zod';
import { rateLimitBucket } from './rate-limit/group';
import {
  createInMemoryRateLimiter,
  DEFAULT_MAX_COUNTERS,
} from './rate-limit/in-memory-rate-limiter';
import {
  GLOBAL_SUBJECT,
  RATE_LIMIT_GROUPS,
  type PolicyRateLimitRule,
  type RateLimitDecision,
  type RateLimiter,
  type RateLimitGroup,
  type RateLimitKey,
  type RateLimitRule,
} from './rate-limit/rate-limiter';
import { json } from './responses';
import {
  apiRequest,
  CEO_POLICY,
  createTestPipeline,
  principalFixture,
  PUBLIC_POLICY,
} from './testing';

type Consumption = { key: RateLimitKey; rule: RateLimitRule };

/** Limiter that records every consumption and answers with a scripted decision. */
function recordingLimiter(decide: (n: number) => RateLimitDecision = () => ({ allowed: true })) {
  const consumptions: Consumption[] = [];
  const limiter: RateLimiter = {
    consume(key, rule) {
      consumptions.push({ key, rule });
      return Promise.resolve(decide(consumptions.length));
    },
  };
  return { limiter, consumptions };
}

const IP_20_PER_15_MIN: PolicyRateLimitRule = {
  scope: 'ip',
  group: 'login',
  limit: 20,
  windowSeconds: 900,
};
const ACCOUNT_10_PER_15_MIN: PolicyRateLimitRule = {
  scope: 'account',
  group: 'login',
  limit: 10,
  windowSeconds: 900,
};
const USER_60_PER_MIN: PolicyRateLimitRule = {
  scope: 'user',
  group: 'writes',
  limit: 60,
  windowSeconds: 60,
};

/** Spec §3.9 and the contract: the numbers each named group stands for. */
const GROUP_NUMBERS: Record<RateLimitGroup, readonly Omit<RateLimitRule, 'group'>[]> = {
  login: [
    { scope: 'ip', limit: 20, windowSeconds: 900 },
    { scope: 'account', limit: 10, windowSeconds: 900 },
  ],
  'totp-enroll': [{ scope: 'user', limit: 10, windowSeconds: 900 }],
  'totp-verify': [{ scope: 'user', limit: 5, windowSeconds: 300 }],
  'password-change': [{ scope: 'user', limit: 5, windowSeconds: 900 }],
  'client-user-admin': [{ scope: 'user', limit: 20, windowSeconds: 3600 }],
  writes: [{ scope: 'user', limit: 60, windowSeconds: 60 }],
  reads: [{ scope: 'user', limit: 300, windowSeconds: 60 }],
  health: [{ scope: 'ip', limit: 60, windowSeconds: 60 }],
  // not a route: the per-IP budget of session cookies that make the server call Auth (F-01)
  'session-upstream': [{ scope: 'ip', limit: 60, windowSeconds: 900 }],
};

describe('rate-limit groups (spec §3.9)', () => {
  it('the named groups are exactly those of spec §3.9 (plus totp-enroll, which the contract adds, and session-upstream, which is no route)', () => {
    expect([...RATE_LIMIT_GROUPS].sort()).toEqual(
      [
        'login',
        'totp-enroll',
        'totp-verify',
        'password-change',
        'client-user-admin',
        'writes',
        'reads',
        'health',
        'session-upstream',
      ].sort(),
    );
  });

  it.each<[string, RateLimitRule, string]>([
    ['login by IP', { scope: 'ip', group: 'login', limit: 20, windowSeconds: 900 }, 'ip:login'],
    [
      'login by account',
      { scope: 'account', group: 'login', limit: 10, windowSeconds: 900 },
      'account:login',
    ],
    [
      'TOTP verification',
      { scope: 'user', group: 'totp-verify', limit: 5, windowSeconds: 300 },
      'user:totp-verify',
    ],
    [
      'TOTP enrollment',
      { scope: 'user', group: 'totp-enroll', limit: 10, windowSeconds: 900 },
      'user:totp-enroll',
    ],
    [
      'password change',
      { scope: 'user', group: 'password-change', limit: 5, windowSeconds: 900 },
      'user:password-change',
    ],
    [
      'provision / reset password',
      { scope: 'user', group: 'client-user-admin', limit: 20, windowSeconds: 3600 },
      'user:client-user-admin',
    ],
    [
      'other authenticated writes',
      { scope: 'user', group: 'writes', limit: 60, windowSeconds: 60 },
      'user:writes',
    ],
    [
      'authenticated reads',
      { scope: 'user', group: 'reads', limit: 300, windowSeconds: 60 },
      'user:reads',
    ],
    ['health', { scope: 'ip', group: 'health', limit: 60, windowSeconds: 60 }, 'ip:health'],
  ])('%s → bucket %s', (_name, rule, bucket) => {
    expect(rateLimitBucket(rule)).toBe(bucket);
  });

  it('every x-rate-limit entry of the contract belongs to exactly one named group', () => {
    const contract = parse(
      readFileSync(
        fileURLToPath(new URL('../../../contracts/openapi.v1.yaml', import.meta.url)),
        'utf8',
      ),
    ) as {
      paths: Record<string, Record<string, { 'x-rate-limit'?: Omit<RateLimitRule, 'group'>[] }>>;
    };

    let checked = 0;
    for (const item of Object.values(contract.paths)) {
      for (const operation of Object.values(item)) {
        for (const rule of operation['x-rate-limit'] ?? []) {
          const owners = RATE_LIMIT_GROUPS.filter((group) =>
            GROUP_NUMBERS[group].some(
              (known) =>
                known.scope === rule.scope &&
                known.limit === rule.limit &&
                known.windowSeconds === rule.windowSeconds,
            ),
          );
          expect(owners, JSON.stringify(rule)).toHaveLength(1);
          checked += 1;
        }
      }
    }
    expect(checked).toBeGreaterThanOrEqual(20);
  });

  it('routes in the same group share one counter per subject (e.g. all "writes")', async () => {
    const { withRoute } = createTestPipeline({
      principal: principalFixture(),
      rateLimiter: createInMemoryRateLimiter(),
    });
    const policy = {
      ...CEO_POLICY,
      rateLimit: [{ scope: 'user', group: 'writes', limit: 2, windowSeconds: 60 }],
    } as const;
    const routeA = withRoute(policy, () => json(200, {}));
    const routeB = withRoute(policy, () => json(200, {}));
    expect((await routeA(apiRequest('/a'))).status).toBe(200);
    expect((await routeB(apiRequest('/b'))).status).toBe(200);
    expect((await routeA(apiRequest('/a'))).status).toBe(429);
  });

  it('routes with the same numbers but different groups do NOT share a counter', async () => {
    const { withRoute } = createTestPipeline({
      principal: principalFixture(),
      rateLimiter: createInMemoryRateLimiter(),
    });
    const rule = { scope: 'user', limit: 2, windowSeconds: 60 } as const;
    const writes = withRoute({ ...CEO_POLICY, rateLimit: [{ ...rule, group: 'writes' }] }, () =>
      json(200, {}),
    );
    const admin = withRoute(
      { ...CEO_POLICY, rateLimit: [{ ...rule, group: 'client-user-admin' }] },
      () => json(200, {}),
    );
    expect((await writes(apiRequest('/a'))).status).toBe(200);
    expect((await writes(apiRequest('/a'))).status).toBe(200);
    expect((await writes(apiRequest('/a'))).status).toBe(429);
    // the other group still has its whole budget
    expect((await admin(apiRequest('/b'))).status).toBe(200);
    expect((await admin(apiRequest('/b'))).status).toBe(200);
    expect((await admin(apiRequest('/b'))).status).toBe(429);
  });

  it('keeps the same group in different scopes apart', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const { withRoute } = createTestPipeline({
      principal: principalFixture(),
      rateLimiter: limiter,
    });
    const route = withRoute(
      {
        ...CEO_POLICY,
        rateLimit: [
          { scope: 'ip', group: 'writes', limit: 5, windowSeconds: 60 },
          { scope: 'user', group: 'writes', limit: 5, windowSeconds: 60 },
        ],
      },
      () => json(200, {}),
    );
    await route(apiRequest('/x'));
    expect(consumptions.map(({ key }) => key.bucket)).toEqual(['ip:writes', 'user:writes']);
  });
});

describe('withRoute: rate limiting', () => {
  it('passes the limiter a structured key (scope, group, bucket, plaintext subject) plus the rule', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const route = withRoute({ ...PUBLIC_POLICY, rateLimit: [IP_20_PER_15_MIN] }, () =>
      json(200, {}),
    );
    await route(apiRequest('/x', { headers: { 'x-real-ip': '203.0.113.7' } }));
    expect(consumptions).toEqual([
      {
        key: { scope: 'ip', group: 'login', bucket: 'ip:login', subject: '203.0.113.7' },
        rule: IP_20_PER_15_MIN,
      },
    ]);
  });

  it('takes the client IP only from the platform helper, never from X-Forwarded-For', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const route = withRoute({ ...PUBLIC_POLICY, rateLimit: [IP_20_PER_15_MIN] }, () =>
      json(200, {}),
    );
    await route(
      apiRequest('/x', {
        headers: { 'x-forwarded-for': '198.51.100.9', forwarded: 'for=198.51.100.9' },
      }),
    );
    expect(consumptions[0]?.key.subject).toBe('unknown');
  });

  it('gives each IP its own counter', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(
      {
        ...PUBLIC_POLICY,
        rateLimit: [{ scope: 'ip', group: 'reads', limit: 1, windowSeconds: 60 }],
      },
      () => json(200, {}),
    );
    const from = (ip: string) => route(apiRequest('/x', { headers: { 'x-real-ip': ip } }));
    expect((await from('203.0.113.1')).status).toBe(200);
    expect((await from('203.0.113.2')).status).toBe(200);
    expect((await from('203.0.113.1')).status).toBe(429);
  });

  it('aggregates IPv6 addresses to their /64: one subscriber cannot rotate within its prefix', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const route = withRoute({ ...PUBLIC_POLICY, rateLimit: [IP_20_PER_15_MIN] }, () =>
      json(200, {}),
    );
    const from = (ip: string) => route(apiRequest('/x', { headers: { 'x-real-ip': ip } }));
    await from('2001:db8:1:2::1');
    await from('2001:0DB8:0001:0002:ffff:ffff:ffff:9');
    await from('2001:db8:1:3::1');
    expect(consumptions.map(({ key }) => key.subject)).toEqual([
      '2001:db8:1:2::/64',
      '2001:db8:1:2::/64',
      '2001:db8:1:3::/64',
    ]);
  });

  it('counts an IPv4-mapped IPv6 address as the IPv4 address', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const route = withRoute({ ...PUBLIC_POLICY, rateLimit: [IP_20_PER_15_MIN] }, () =>
      json(200, {}),
    );
    await route(apiRequest('/x', { headers: { 'x-real-ip': '::ffff:203.0.113.7' } }));
    await route(apiRequest('/x', { headers: { 'x-real-ip': '203.0.113.7' } }));
    expect(consumptions.map(({ key }) => key.subject)).toEqual(['203.0.113.7', '203.0.113.7']);
  });

  describe('a request the platform gave no client IP for', () => {
    const policy = {
      ...PUBLIC_POLICY,
      rateLimit: [{ scope: 'ip', group: 'reads', limit: 1000, windowSeconds: 60 }],
    } as const;

    it('shares the "unknown" bucket outside production (dev and tests)', async () => {
      const { limiter, consumptions } = recordingLimiter();
      const { withRoute } = createTestPipeline({ rateLimiter: limiter });
      const route = withRoute(policy, () => json(200, {}));
      expect((await route(apiRequest('/x'))).status).toBe(200);
      expect(consumptions[0]?.key.subject).toBe('unknown');
    });

    it('fails closed in production: 503 SERVICE_UNAVAILABLE, the handler never runs', async () => {
      const { limiter, consumptions } = recordingLimiter();
      const { withRoute } = createTestPipeline({ rateLimiter: limiter, requireClientIp: true });
      const handler = vi.fn(() => json(200, {}));
      const route = withRoute(policy, handler);
      const response = await route(apiRequest('/x'));
      expect(response.status).toBe(503);
      expect(await response.json()).toMatchObject({ code: 'SERVICE_UNAVAILABLE' });
      expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
      expect(handler).not.toHaveBeenCalled();
      expect(consumptions).toHaveLength(0);
    });

    it('also treats an unparseable x-real-ip as missing in production', async () => {
      const { withRoute } = createTestPipeline({ requireClientIp: true });
      const route = withRoute(policy, () => json(200, {}));
      const response = await route(apiRequest('/x', { headers: { 'x-real-ip': 'not-an-ip' } }));
      expect(response.status).toBe(503);
    });

    it('serves requests that carry an IP in production', async () => {
      const { withRoute } = createTestPipeline({ requireClientIp: true });
      const route = withRoute(policy, () => json(200, {}));
      const response = await route(apiRequest('/x', { headers: { 'x-real-ip': '203.0.113.7' } }));
      expect(response.status).toBe(200);
    });

    it('does not matter to a route that has no ip rule', async () => {
      const { withRoute } = createTestPipeline({
        principal: principalFixture(),
        requireClientIp: true,
      });
      const route = withRoute(CEO_POLICY, () => json(200, {}));
      expect((await route(apiRequest('/x'))).status).toBe(200);
    });
  });

  it('ip rules run BEFORE authentication: a throttled IP never reaches the resolver', async () => {
    const { withRoute, principalResolver } = createTestPipeline({ principal: null });
    const route = withRoute(
      {
        ...CEO_POLICY,
        rateLimit: [{ scope: 'ip', group: 'reads', limit: 1, windowSeconds: 60 }],
      },
      () => json(200, {}),
    );
    const first = await route(apiRequest('/x'));
    const second = await route(apiRequest('/x'));
    expect(first.status).toBe(401);
    expect(second.status).toBe(429);
    expect(principalResolver.calls).toHaveLength(1);
  });

  it('user rules run AFTER authentication and are keyed by the user id', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const principal = principalFixture({ userId: '22222222-2222-4222-8222-222222222222' });
    const { withRoute } = createTestPipeline({ principal, rateLimiter: limiter });
    const route = withRoute({ ...CEO_POLICY, rateLimit: [USER_60_PER_MIN] }, () => json(200, {}));
    await route(apiRequest('/x', { headers: { 'x-real-ip': '203.0.113.7' } }));
    expect(consumptions.map(({ key }) => key)).toEqual([
      {
        scope: 'user',
        group: 'writes',
        bucket: 'user:writes',
        subject: '22222222-2222-4222-8222-222222222222',
      },
    ]);
  });

  it('user rules are not evaluated for an unauthenticated request', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const { withRoute } = createTestPipeline({ principal: null, rateLimiter: limiter });
    const route = withRoute({ ...CEO_POLICY, rateLimit: [USER_60_PER_MIN] }, () => json(200, {}));
    expect((await route(apiRequest('/x'))).status).toBe(401);
    expect(consumptions).toHaveLength(0);
  });

  it('user rules run before authorization: a forbidden role still spends the budget', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const { withRoute } = createTestPipeline({
      principal: principalFixture({ role: 'client', clientId: 'c1' }),
      rateLimiter: limiter,
    });
    const route = withRoute({ ...CEO_POLICY, rateLimit: [USER_60_PER_MIN] }, () => json(200, {}));
    expect((await route(apiRequest('/x'))).status).toBe(403);
    expect(consumptions).toHaveLength(1);
  });

  it('keeps one counter per user', async () => {
    let current = principalFixture({ userId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' });
    const { withRoute } = createTestPipeline({ principal: () => current });
    const route = withRoute(
      {
        ...CEO_POLICY,
        rateLimit: [{ scope: 'user', group: 'reads', limit: 1, windowSeconds: 60 }],
      },
      () => json(200, {}),
    );
    expect((await route(apiRequest('/x'))).status).toBe(200);
    expect((await route(apiRequest('/x'))).status).toBe(429);
    current = principalFixture({ userId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' });
    expect((await route(apiRequest('/x'))).status).toBe(200);
  });
});

describe('withRoute: account rate limit (public routes)', () => {
  const loginBody = z.object({ email: z.string().max(254), password: z.string().min(1) }).strict();
  const loginPolicy = {
    access: 'public',
    body: loginBody,
    rateLimit: [IP_20_PER_15_MIN, ACCOUNT_10_PER_15_MIN],
    accountKey: (body: z.output<typeof loginBody>) => body.email.trim().toLowerCase(),
  } as const;

  const login = (email: string, password = 'x', headers: Record<string, string> = {}) =>
    apiRequest('/auth/login', { method: 'POST', json: { email, password }, headers });

  it('is keyed by accountKey(validated body), so e-mail variants share one bucket', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const route = withRoute(loginPolicy, () => json(200, {}));
    await route(login('  Maria@Cliente.com.br '));
    await route(login('maria@cliente.com.br'));
    const account = consumptions.filter(({ key }) => key.scope === 'account');
    expect(account.map(({ key }) => key.subject)).toEqual([
      'maria@cliente.com.br',
      'maria@cliente.com.br',
    ]);
    expect(account[0]?.key).toMatchObject({ group: 'login', bucket: 'account:login' });
  });

  it('runs the ip rule first, then (after validation) the account rule', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const route = withRoute(loginPolicy, () => json(200, {}));
    await route(login('a@b.co'));
    expect(consumptions.map(({ key }) => key.scope)).toEqual(['ip', 'account']);
  });

  it('a body that fails validation does not spend the account budget', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const route = withRoute(loginPolicy, () => json(200, {}));
    const response = await route(
      apiRequest('/auth/login', { method: 'POST', json: { email: 'a@b.co' } }),
    );
    expect(response.status).toBe(400);
    expect(consumptions.map(({ key }) => key.scope)).toEqual(['ip']);
  });

  it('AC-03 shape: the 11th attempt on one account is throttled even from other IPs', async () => {
    const { withRoute } = createTestPipeline();
    const handler = vi.fn(() => json(401, {}));
    const route = withRoute(loginPolicy, handler);
    for (let attempt = 1; attempt <= 10; attempt += 1) {
      const response = await route(
        login('victim@x.co', 'x', { 'x-real-ip': `203.0.113.${attempt}` }),
      );
      expect(response.status, `attempt ${attempt}`).toBe(401);
    }
    const eleventh = await route(login('Victim@X.co', 'x', { 'x-real-ip': '203.0.113.99' }));
    expect(eleventh.status).toBe(429);
    expect(handler).toHaveBeenCalledTimes(10);
    // another account is unaffected
    expect((await route(login('other@x.co', 'x', { 'x-real-ip': '203.0.113.50' }))).status).toBe(
      401,
    );
  });

  it('AC-03 shape: the 21st attempt from one IP is throttled', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(loginPolicy, () => json(401, {}));
    for (let attempt = 1; attempt <= 20; attempt += 1) {
      const response = await route(
        login(`user${attempt}@x.co`, 'x', { 'x-real-ip': '198.51.100.1' }),
      );
      expect(response.status, `attempt ${attempt}`).toBe(401);
    }
    const twentyFirst = await route(login('user21@x.co', 'x', { 'x-real-ip': '198.51.100.1' }));
    expect(twentyFirst.status).toBe(429);
  });
});

describe('withRoute: 429 and Retry-After', () => {
  const deny = (retryAfterSeconds: number) =>
    recordingLimiter(() => ({ allowed: false, retryAfterSeconds }));

  it('answers 429 RATE_LIMITED with Retry-After and does not run the handler', async () => {
    const { limiter } = deny(42);
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const handler = vi.fn(() => json(200, {}));
    const route = withRoute({ ...PUBLIC_POLICY, rateLimit: [IP_20_PER_15_MIN] }, handler);
    const response = await route(apiRequest('/x'));
    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('42');
    expect(await response.json()).toMatchObject({ code: 'RATE_LIMITED', status: 429 });
    expect(handler).not.toHaveBeenCalled();
  });

  it.each([
    [0, '1'],
    [0.2, '1'],
    [-5, '1'],
    [61.2, '62'],
    [Number.NaN, '900'],
    [Number.POSITIVE_INFINITY, '900'],
  ])('Retry-After %s is sent as the integer %s', async (retryAfterSeconds, expected) => {
    const { limiter } = deny(retryAfterSeconds);
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const route = withRoute({ ...PUBLIC_POLICY, rateLimit: [IP_20_PER_15_MIN] }, () =>
      json(200, {}),
    );
    const response = await route(apiRequest('/x'));
    expect(response.headers.get('retry-after')).toBe(expected);
  });
});

describe('createInMemoryRateLimiter', () => {
  const rule: RateLimitRule = { scope: 'ip', group: 'reads', limit: 2, windowSeconds: 60 };
  const key: RateLimitKey = {
    scope: 'ip',
    group: rule.group,
    bucket: rateLimitBucket(rule),
    subject: '203.0.113.1',
  };

  function clockAt(start: number) {
    let now = start;
    return {
      clock: { now: () => new Date(now) },
      advance: (ms: number) => {
        now += ms;
      },
    };
  }

  it('allows `limit` requests per window, then denies with the seconds left', async () => {
    const { clock, advance } = clockAt(1_000_000);
    const limiter = createInMemoryRateLimiter({ clock });
    expect(await limiter.consume(key, rule)).toEqual({ allowed: true });
    advance(10_000);
    expect(await limiter.consume(key, rule)).toEqual({ allowed: true });
    advance(10_000);
    expect(await limiter.consume(key, rule)).toEqual({ allowed: false, retryAfterSeconds: 40 });
  });

  it('opens a new window once the old one expires', async () => {
    const { clock, advance } = clockAt(0);
    const limiter = createInMemoryRateLimiter({ clock });
    await limiter.consume(key, rule);
    await limiter.consume(key, rule);
    expect((await limiter.consume(key, rule)).allowed).toBe(false);
    advance(60_000);
    expect(await limiter.consume(key, rule)).toEqual({ allowed: true });
  });

  it('never reports less than 1 second to wait', async () => {
    const { clock, advance } = clockAt(0);
    const limiter = createInMemoryRateLimiter({ clock });
    await limiter.consume(key, rule);
    await limiter.consume(key, rule);
    advance(59_999);
    expect(await limiter.consume(key, rule)).toEqual({ allowed: false, retryAfterSeconds: 1 });
  });

  it('keeps subjects and groups apart', async () => {
    const limiter = createInMemoryRateLimiter();
    await limiter.consume(key, rule);
    await limiter.consume(key, rule);
    expect((await limiter.consume({ ...key, subject: '203.0.113.2' }, rule)).allowed).toBe(true);
    expect((await limiter.consume({ ...key, bucket: 'ip:other' }, rule)).allowed).toBe(true);
    expect((await limiter.consume(key, rule)).allowed).toBe(false);
  });

  describe('bounded memory', () => {
    const subject = (n: number): RateLimitKey => ({ ...key, subject: `203.0.113.${n}` });

    it('evicts the oldest counters once maxCounters is reached', async () => {
      const limiter = createInMemoryRateLimiter({ maxCounters: 3 });
      // fill: subjects 1..3, each already at its limit
      for (const n of [1, 2, 3]) {
        await limiter.consume(subject(n), rule);
        await limiter.consume(subject(n), rule);
      }
      expect((await limiter.consume(subject(3), rule)).allowed).toBe(false);

      // a 4th subject needs room: the OLDEST counter (subject 1) is evicted, 2 and 3 survive
      expect((await limiter.consume(subject(4), rule)).allowed).toBe(true);
      expect((await limiter.consume(subject(2), rule)).allowed).toBe(false);
      expect((await limiter.consume(subject(3), rule)).allowed).toBe(false);
      expect((await limiter.consume(subject(1), rule)).allowed).toBe(true); // forgotten, restarts
    });

    it('prefers sweeping expired counters to evicting live ones', async () => {
      const { clock, advance } = clockAt(0);
      const limiter = createInMemoryRateLimiter({ clock, maxCounters: 2 });
      await limiter.consume(subject(1), rule);
      await limiter.consume(subject(1), rule);
      advance(30_000);
      await limiter.consume(subject(2), rule);
      await limiter.consume(subject(2), rule);
      advance(31_000); // subject 1's window (60 s) is over, subject 2's is not

      expect((await limiter.consume(subject(3), rule)).allowed).toBe(true);
      // subject 2 was still live and kept its counter
      expect((await limiter.consume(subject(2), rule)).allowed).toBe(false);
    });

    it('never holds more counters than the cap, however many subjects arrive', async () => {
      const limiter = createInMemoryRateLimiter({ maxCounters: 50 });
      for (let n = 0; n < 5000; n += 1) {
        await limiter.consume({ ...key, subject: `subject-${n}` }, rule);
      }
      // the 4951st..5000th subjects are the 50 newest: still counted; an old one was forgotten
      for (let n = 4950; n < 5000; n += 1) {
        await limiter.consume({ ...key, subject: `subject-${n}` }, rule);
        expect(
          (await limiter.consume({ ...key, subject: `subject-${n}` }, rule)).allowed,
          `subject-${n}`,
        ).toBe(false);
      }
      expect((await limiter.consume({ ...key, subject: 'subject-0' }, rule)).allowed).toBe(true);
    });

    it('defaults to a cap of 10,000 counters', () => {
      expect(DEFAULT_MAX_COUNTERS).toBe(10_000);
    });
  });
});

describe('withRoute: the global budget (F-02) and the subject hash of auth.rate_limited (F-09)', () => {
  const BUDGET = { group: 'login', limit: 2, windowSeconds: 300 } as const;

  it('hands the handler a way to spend an aggregate budget: scope global, one constant subject', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const route = withRoute(PUBLIC_POLICY, async ({ consumeGlobalBudget }) => {
      await consumeGlobalBudget(BUDGET);
      return json(200, {});
    });

    await route(apiRequest('/x', { headers: { 'x-real-ip': '203.0.113.7' } }));

    // the first consumption is the route's own ip rule; the second is the handler's global budget
    expect(consumptions.map(({ key }) => key.bucket)).toEqual(['ip:reads', 'global:login']);
    expect(consumptions[1]).toEqual({
      key: { scope: 'global', group: 'login', bucket: 'global:login', subject: GLOBAL_SUBJECT },
      rule: { scope: 'global', ...BUDGET },
    });
  });

  it('over budget it is 429 with Retry-After and the handler stops there', async () => {
    const { limiter } = recordingLimiter((n) =>
      n === 2 ? { allowed: false, retryAfterSeconds: 42 } : { allowed: true },
    );
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const afterBudget = vi.fn();
    const route = withRoute(PUBLIC_POLICY, async ({ consumeGlobalBudget }) => {
      await consumeGlobalBudget(BUDGET);
      afterBudget();
      return json(200, {});
    });

    const response = await route(apiRequest('/x'));

    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('42');
    expect(await response.json()).toMatchObject({ code: 'RATE_LIMITED' });
    expect(afterBudget).not.toHaveBeenCalled();
  });

  it('E-22: a limiter that fails on a global budget denies with 503 (fail closed)', async () => {
    const limiter: RateLimiter = {
      consume: (key) =>
        key.scope === 'global'
          ? Promise.reject(new Error('down'))
          : Promise.resolve({ allowed: true }),
    };
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const route = withRoute(PUBLIC_POLICY, async ({ consumeGlobalBudget }) => {
      await consumeGlobalBudget(BUDGET);
      return json(200, {});
    });

    expect((await route(apiRequest('/x'))).status).toBe(503);
  });

  it('F-09: auth.rate_limited carries scope, group and a keyed hash of the subject, never the subject', async () => {
    const { limiter } = recordingLimiter(() => ({ allowed: false, retryAfterSeconds: 9 }));
    const { withRoute, logs } = createTestPipeline({ rateLimiter: limiter });
    const route = withRoute({ ...PUBLIC_POLICY, rateLimit: [IP_20_PER_15_MIN] }, () =>
      json(200, {}),
    );

    await route(apiRequest('/x', { headers: { 'x-real-ip': '203.0.113.7' } }));

    expect(logs.events('auth.rate_limited')).toEqual([
      expect.objectContaining({
        event: 'auth.rate_limited',
        scope: 'ip',
        group: 'login',
        subjectHash: 'fingerprint-of-11-chars',
      }),
    ]);
    expect(logs.lines.join('\n')).not.toContain('203.0.113.7');
  });
});
