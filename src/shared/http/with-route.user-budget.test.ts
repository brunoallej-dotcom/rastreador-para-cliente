import { describe, expect, it, vi } from 'vitest';
import type {
  RateLimitDecision,
  RateLimiter,
  RateLimitKey,
  RateLimitRule,
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

describe('withRoute: the per-user budget a handler spends by itself (F-22)', () => {
  const BUDGET = { group: 'totp-verify-daily', limit: 20, windowSeconds: 86_400 } as const;
  const USER_ID = '11111111-1111-4111-8111-111111111111';

  it('spends a counter of scope user, keyed by the authenticated user, after the rules of the route', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const { withRoute } = createTestPipeline({
      principal: principalFixture({ userId: USER_ID }),
      rateLimiter: limiter,
    });
    const route = withRoute(CEO_POLICY, async ({ consumeUserBudget }) => {
      await consumeUserBudget(BUDGET);
      return json(200, {});
    });

    expect((await route(apiRequest('/x'))).status).toBe(200);

    expect(consumptions.map(({ key }) => key.bucket)).toEqual([
      'user:reads',
      'user:totp-verify-daily',
    ]);
    expect(consumptions[1]).toEqual({
      key: {
        scope: 'user',
        group: 'totp-verify-daily',
        bucket: 'user:totp-verify-daily',
        subject: USER_ID,
      },
      rule: { scope: 'user', ...BUDGET },
    });
  });

  it('over budget it is 429 with Retry-After and the handler stops there', async () => {
    const { limiter } = recordingLimiter((n) =>
      n === 2 ? { allowed: false, retryAfterSeconds: 3_600 } : { allowed: true },
    );
    const { withRoute } = createTestPipeline({
      principal: principalFixture(),
      rateLimiter: limiter,
    });
    const afterBudget = vi.fn();
    const route = withRoute(CEO_POLICY, async ({ consumeUserBudget }) => {
      await consumeUserBudget(BUDGET);
      afterBudget();
      return json(200, {});
    });

    const response = await route(apiRequest('/x'));

    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('3600');
    expect(await response.json()).toMatchObject({ code: 'RATE_LIMITED' });
    expect(afterBudget).not.toHaveBeenCalled();
  });

  it('E-22: a limiter that fails on a user budget denies with 503 (fail closed)', async () => {
    let calls = 0;
    const limiter: RateLimiter = {
      consume: () => {
        calls += 1;
        return calls === 1 ? Promise.resolve({ allowed: true }) : Promise.reject(new Error('down'));
      },
    };
    const { withRoute } = createTestPipeline({
      principal: principalFixture(),
      rateLimiter: limiter,
    });
    const route = withRoute(CEO_POLICY, async ({ consumeUserBudget }) => {
      await consumeUserBudget(BUDGET);
      return json(200, {});
    });

    expect((await route(apiRequest('/x'))).status).toBe(503);
  });

  it('a user budget on a public route is a programming error: 500, and nothing is counted', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const route = withRoute(PUBLIC_POLICY, async ({ consumeUserBudget }) => {
      await consumeUserBudget(BUDGET);
      return json(200, {});
    });

    expect((await route(apiRequest('/x'))).status).toBe(500);
    expect(consumptions.map(({ key }) => key.bucket)).toEqual(['ip:reads']);
  });

  it('F-09: the denial event carries the group and a keyed hash of the user, never the user id', async () => {
    const { limiter } = recordingLimiter((n) =>
      n === 2 ? { allowed: false, retryAfterSeconds: 5 } : { allowed: true },
    );
    const { withRoute, logs } = createTestPipeline({
      principal: principalFixture({ userId: USER_ID }),
      rateLimiter: limiter,
    });
    const route = withRoute(CEO_POLICY, async ({ consumeUserBudget }) => {
      await consumeUserBudget(BUDGET);
      return json(200, {});
    });

    await route(apiRequest('/x'));

    expect(logs.events('auth.rate_limited')).toEqual([
      expect.objectContaining({
        scope: 'user',
        group: 'totp-verify-daily',
        subjectHash: `fingerprint-of-${USER_ID.length}-chars`,
      }),
    ]);
    // (the access log line carries the internal user id by design; the denial event does not)
    expect(JSON.stringify(logs.events('auth.rate_limited'))).not.toContain(USER_ID);
  });
});
