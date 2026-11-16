import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type {
  RateLimitDecision,
  RateLimiter,
  RateLimitKey,
  RateLimitRule,
} from '@/shared/http/rate-limit/rate-limiter';
import { apiRequest, createTestPipeline, principalFixture } from '@/shared/http/testing';
import { VERIFY_DAILY_BUDGET } from './rate-limit-budgets';
import { createVerifyTotpHandler } from './verify-totp.handler';

// Obviously fake, lowercase-only values (the secret-detection hook rightly ignores them).
const FAKE_ENV = {
  APP_ORIGIN: 'http://localhost:3000',
  SUPABASE_URL: 'http://127.0.0.1:54321',
  SUPABASE_PUBLISHABLE_KEY: 'fake-publishable-key-for-unit-tests',
  SUPABASE_SECRET_KEY: 'fake-secret-key-for-unit-tests',
  RATE_LIMIT_KEY_SECRET: 'unit-test-only-rate-limit-key-not-a-real-value',
};

const USER_ID = '11111111-1111-4111-8111-111111111111';
const BODY = { factorId: '33333333-3333-4333-8333-333333333333', code: '123456' };
const SECONDS_PER_DAY = 86_400;

type Consumption = { key: RateLimitKey; rule: RateLimitRule };

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

const verifyRequest = () => apiRequest('/auth/mfa/totp/verify', { method: 'POST', json: BODY });
const ceoReadyToVerify = () =>
  principalFixture({ userId: USER_ID, aal: 'aal1', pendingActions: ['VERIFY_MFA'] });

beforeEach(() => {
  for (const [name, value] of Object.entries(FAKE_ENV)) vi.stubEnv(name, value);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

/** An Auth server or database that must not be reached (the daily cap decides before). */
const forbidOutbound = () =>
  vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('no outbound call expected'));

describe('POST /auth/mfa/totp/verify: the daily cap (F-22)', () => {
  it('is 20 per 86,400 s in the totp-verify-daily group', () => {
    expect(VERIFY_DAILY_BUDGET).toEqual({
      group: 'totp-verify-daily',
      limit: 20,
      windowSeconds: SECONDS_PER_DAY,
    });
  });

  it('is spent by the handler on top of the contract rule, keyed by the user, before the code is looked at', async () => {
    const { limiter, consumptions } = recordingLimiter();
    const { withRoute } = createTestPipeline({
      principal: ceoReadyToVerify(),
      rateLimiter: limiter,
    });
    forbidOutbound();

    await createVerifyTotpHandler(withRoute)(verifyRequest());

    expect(consumptions.map(({ key }) => key.bucket)).toEqual([
      'user:totp-verify',
      'user:totp-verify-daily',
    ]);
    expect(consumptions[0]?.rule).toEqual({
      scope: 'user',
      group: 'totp-verify',
      limit: 5,
      windowSeconds: 300,
    });
    expect(consumptions[1]).toEqual({
      key: {
        scope: 'user',
        group: 'totp-verify-daily',
        bucket: 'user:totp-verify-daily',
        subject: USER_ID,
      },
      rule: { scope: 'user', ...VERIFY_DAILY_BUDGET },
    });
  });

  it('over the daily cap the answer is 429 RATE_LIMITED with Retry-After, and nothing reaches Auth or the database', async () => {
    const { limiter } = recordingLimiter((n) =>
      n === 2 ? { allowed: false, retryAfterSeconds: 7_200 } : { allowed: true },
    );
    const { withRoute, logs } = createTestPipeline({
      principal: ceoReadyToVerify(),
      rateLimiter: limiter,
    });
    const outbound = forbidOutbound();

    const response = await createVerifyTotpHandler(withRoute)(verifyRequest());

    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('7200');
    expect(await response.json()).toMatchObject({ code: 'RATE_LIMITED' });
    expect(outbound).not.toHaveBeenCalled();
    expect(logs.events('auth.rate_limited')).toEqual([
      expect.objectContaining({ scope: 'user', group: 'totp-verify-daily' }),
    ]);
  });

  it('a request the contract rule already throttled does not spend the daily cap', async () => {
    const { limiter, consumptions } = recordingLimiter(() => ({
      allowed: false,
      retryAfterSeconds: 30,
    }));
    const { withRoute } = createTestPipeline({
      principal: ceoReadyToVerify(),
      rateLimiter: limiter,
    });
    const outbound = forbidOutbound();

    const response = await createVerifyTotpHandler(withRoute)(verifyRequest());

    expect(response.status).toBe(429);
    expect(consumptions.map(({ key }) => key.bucket)).toEqual(['user:totp-verify']);
    expect(outbound).not.toHaveBeenCalled();
  });

  it('E-22: a limiter that fails on the daily cap denies with 503 (fail closed), and nothing reaches Auth', async () => {
    let calls = 0;
    const limiter: RateLimiter = {
      consume: () => {
        calls += 1;
        return calls === 1 ? Promise.resolve({ allowed: true }) : Promise.reject(new Error('down'));
      },
    };
    const { withRoute } = createTestPipeline({
      principal: ceoReadyToVerify(),
      rateLimiter: limiter,
    });
    const outbound = forbidOutbound();

    const response = await createVerifyTotpHandler(withRoute)(verifyRequest());

    expect(response.status).toBe(503);
    expect(outbound).not.toHaveBeenCalled();
  });
});
