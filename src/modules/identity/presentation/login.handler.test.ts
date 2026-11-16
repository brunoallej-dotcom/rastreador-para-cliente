import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { timing } from '@/shared/http/response-floor';
import type {
  RateLimitDecision,
  RateLimiter,
  RateLimitKey,
} from '@/shared/http/rate-limit/rate-limiter';
import { apiRequest, createTestPipeline } from '@/shared/http/testing';
import {
  createLoginHandler,
  LOGIN_GLOBAL_BUDGET,
  REFUSED_LOGIN_FLOOR_MS,
  REFUSED_LOGIN_JITTER_MS,
} from './login.handler';

// Obviously fake, lowercase-only values (the secret-detection hook rightly ignores them).
const FAKE_ENV = {
  APP_ORIGIN: 'http://localhost:3000',
  SUPABASE_URL: 'http://127.0.0.1:54321',
  SUPABASE_PUBLISHABLE_KEY: 'fake-publishable-key-for-unit-tests',
  SUPABASE_SECRET_KEY: 'fake-secret-key-for-unit-tests',
  RATE_LIMIT_KEY_SECRET: 'unit-test-only-rate-limit-key-not-a-real-value',
};

const BODY = { email: 'maria@cliente.test', password: 'any-password-1' };
const loginRequest = () =>
  apiRequest('/auth/login', {
    method: 'POST',
    json: BODY,
    headers: { 'x-real-ip': '203.0.113.9' },
  });

/** A limiter that allows everything except what `deny` picks, recording every key it saw. */
function limiterDenying(deny: (key: RateLimitKey) => boolean) {
  const seen: RateLimitKey[] = [];
  const limiter: RateLimiter = {
    consume(key): Promise<RateLimitDecision> {
      seen.push(key);
      return Promise.resolve(
        deny(key) ? { allowed: false, retryAfterSeconds: 77 } : { allowed: true },
      );
    },
  };
  return { limiter, seen };
}

/** Answers every call to the Auth server with `answer`; records what was asked. */
function stubAuth(answer: () => Response | Error) {
  const calls: string[] = [];
  vi.spyOn(globalThis, 'fetch').mockImplementation((input) => {
    calls.push(String(input instanceof Request ? input.url : input));
    const outcome = answer();
    return outcome instanceof Error ? Promise.reject(outcome) : Promise.resolve(outcome);
  });
  return calls;
}

const authError = (status: number, errorCode: string) =>
  Response.json({ code: status, error_code: errorCode, msg: 'simulated' }, { status });

beforeEach(() => {
  for (const [name, value] of Object.entries(FAKE_ENV)) vi.stubEnv(name, value);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe('the global login budget (F-02)', () => {
  it('is 300 per 300 s in the `login` group', () => {
    expect(LOGIN_GLOBAL_BUDGET).toEqual({ group: 'login', limit: 300, windowSeconds: 300 });
  });

  it('stays strictly below the sign-in quota of the Auth server, so our 429 comes before its 429', () => {
    const config = readFileSync(
      fileURLToPath(new URL('../../../../supabase/config.toml', import.meta.url)),
      'utf8',
    );
    const quota = Number(/^sign_in_sign_ups\s*=\s*(\d+)/m.exec(config)?.[1]);
    // `[auth.rate_limit]` counts per 5 minutes (300 s): the same window as the budget
    expect(Number.isInteger(quota)).toBe(true);
    expect(LOGIN_GLOBAL_BUDGET.limit).toBeLessThan(quota);
    expect(LOGIN_GLOBAL_BUDGET.windowSeconds).toBeLessThanOrEqual(300);
  });

  it('F-02: over budget the login is 429 RATE_LIMITED with Retry-After, and nothing reaches Auth', async () => {
    const { limiter, seen } = limiterDenying((key) => key.scope === 'global');
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const calls = stubAuth(() => authError(400, 'invalid_credentials'));

    const response = await createLoginHandler(withRoute)(loginRequest());

    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('77');
    expect(await response.json()).toMatchObject({ code: 'RATE_LIMITED', status: 429 });
    expect(response.headers.getSetCookie()).toEqual([]);
    expect(calls).toEqual([]);
    // the ip and account rules ran first; the global budget is a `global:login` counter of one subject
    expect(seen.map((key) => key.bucket)).toEqual(['ip:login', 'account:login', 'global:login']);
    expect(seen[2]).toMatchObject({ scope: 'global', group: 'login', subject: 'global' });
  });

  it('E-22: a limiter that fails on the global budget denies with 503 and Auth is not called', async () => {
    const limiter: RateLimiter = {
      consume: (key) =>
        key.scope === 'global'
          ? Promise.reject(new Error('limiter down'))
          : Promise.resolve({ allowed: true }),
    };
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    const calls = stubAuth(() => authError(400, 'invalid_credentials'));

    const response = await createLoginHandler(withRoute)(loginRequest());

    expect(response.status).toBe(503);
    expect(calls).toEqual([]);
  });

  it('under budget the login goes on to Auth', async () => {
    const { limiter } = limiterDenying(() => false);
    const { withRoute } = createTestPipeline({ rateLimiter: limiter });
    vi.spyOn(timing, 'sleep').mockResolvedValue(undefined);
    const calls = stubAuth(() => authError(400, 'invalid_credentials'));

    const response = await createLoginHandler(withRoute)(loginRequest());

    expect(response.status).toBe(401);
    expect(calls.some((url) => url.includes('/auth/v1/token'))).toBe(true);
  });
});

describe('the floor of a refused login (F-05)', () => {
  const run = async (answer: () => Response | Error) => {
    const { withRoute } = createTestPipeline({
      rateLimiter: limiterDenying(() => false).limiter,
    });
    stubAuth(answer);
    return createLoginHandler(withRoute)(loginRequest());
  };

  it('is 400 ms plus up to 100 ms of jitter', () => {
    expect(REFUSED_LOGIN_FLOOR_MS).toBe(400);
    expect(REFUSED_LOGIN_JITTER_MS).toBe(100);
  });

  it.each([
    ['a wrong password or unknown e-mail', () => authError(400, 'invalid_credentials')],
    ['a banned user', () => authError(403, 'user_banned')],
    ['an unconfirmed e-mail', () => authError(400, 'email_not_confirmed')],
  ])(
    '%s is answered only after the floor, measured from the start of the handler',
    async (_label, answer) => {
      vi.spyOn(timing, 'random').mockReturnValue(0.5);
      // the handler starts the floor at 0 ms and the refusal is ready at 120 ms
      const clock = vi.spyOn(timing, 'now');
      clock.mockReturnValueOnce(0).mockReturnValue(120);
      const sleep = vi.spyOn(timing, 'sleep').mockResolvedValue(undefined);

      const response = await run(answer);

      expect(response.status).toBe(401);
      // 400 + 0.5 * 100 = 450 ms in all, 120 of them already spent: 330 left
      expect(sleep).toHaveBeenCalledOnce();
      expect(sleep).toHaveBeenCalledWith(330);
    },
  );

  it('adds nothing when Auth was already slower than the floor', async () => {
    vi.spyOn(timing, 'random').mockReturnValue(1);
    vi.spyOn(timing, 'now').mockReturnValueOnce(0).mockReturnValue(900);
    const sleep = vi.spyOn(timing, 'sleep').mockResolvedValue(undefined);

    expect((await run(() => authError(400, 'invalid_credentials'))).status).toBe(401);

    expect(sleep).not.toHaveBeenCalled();
  });

  it.each([
    ['an outage (502)', () => Response.json({ msg: 'bad gateway' }, { status: 502 })],
    ['a transport failure', () => new TypeError('fetch failed')],
    ['an unexpected Auth answer', () => authError(422, 'email_provider_disabled')],
  ])(
    '%s is a 503 and is NOT delayed: the floor is only for refusals of credentials',
    async (_label, answer) => {
      const sleep = vi.spyOn(timing, 'sleep').mockResolvedValue(undefined);

      const response = await run(answer);

      expect(response.status).toBe(503);
      expect(sleep).not.toHaveBeenCalled();
    },
  );
});
