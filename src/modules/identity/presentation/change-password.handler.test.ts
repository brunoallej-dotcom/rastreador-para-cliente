import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PasswordGateway } from '../domain/password-ports';
import { createFakePasswordGateway } from '../application/password-fakes';
import { UnexpectedAuthAnswerError } from '../domain/errors';
import type { PasswordGatewayOptions } from '../infrastructure/supabase-password-gateway';
import type {
  RateLimitDecision,
  RateLimiter,
  RateLimitKey,
} from '@/shared/http/rate-limit/rate-limiter';
import { apiRequest, createTestPipeline, principalFixture } from '@/shared/http/testing';
import { ServiceUnavailableError } from '@/shared/kernel';
import { createChangePasswordHandler } from './change-password.handler';
import { LOGIN_GLOBAL_BUDGET } from './rate-limit-budgets';

// The gateway is the edge (Supabase): it is replaced by the in-memory fake of the port, wired the
// way the real one is (the budget hook runs right before the check of the current password).
// Everything else (the pipeline, the schema, the use case, the handler) is the real code.
const gatewayOptions: PasswordGatewayOptions[] = [];
let gateway: PasswordGateway;

vi.mock('../infrastructure/supabase-password-gateway', () => ({
  createSupabasePasswordGateway: (_supabase: unknown, options: PasswordGatewayOptions) => {
    gatewayOptions.push(options);
    return {
      async verifyCurrentPassword(password: string) {
        await options.beforeReauthentication?.();
        return gateway.verifyCurrentPassword(password);
      },
      updatePassword: (change: Parameters<PasswordGateway['updatePassword']>[0]) =>
        gateway.updatePassword(change),
      markPasswordChanged: () => gateway.markPasswordChanged(),
    } satisfies PasswordGateway;
  },
}));
vi.mock('../infrastructure/reauth-client', () => ({ createReauthClient: () => ({}) }));
vi.mock('@/shared/db/server-client', () => ({ getRequestSupabase: () => ({}) }));

// Obviously fake values (the secret-detection hook rightly ignores names without "password").
const TEMPORARY = 'Temporary-Pass-1234';
const FRESH = 'A-brand-new-password-9';

const IP = '203.0.113.9';
const client = (pendingActions: ('CHANGE_PASSWORD' | 'ENROLL_MFA' | 'VERIFY_MFA')[] = []) =>
  principalFixture({
    role: 'client',
    clientId: '22222222-2222-4222-8222-222222222222',
    aal: 'aal1',
    pendingActions,
  });

const request = (json: unknown, init: { origin?: string | null } = {}) =>
  apiRequest('/auth/password', {
    method: 'POST',
    json,
    headers: { 'x-real-ip': IP },
    ...init,
  });

/** A limiter that allows everything except what `deny` picks, recording every key it saw. */
function limiterDenying(deny: (key: RateLimitKey) => boolean) {
  const seen: { key: RateLimitKey; limit: number; windowSeconds: number }[] = [];
  const limiter: RateLimiter = {
    consume(key, rule): Promise<RateLimitDecision> {
      seen.push({ key, limit: rule.limit, windowSeconds: rule.windowSeconds });
      return Promise.resolve(
        deny(key) ? { allowed: false, retryAfterSeconds: 77 } : { allowed: true },
      );
    },
  };
  return { limiter, seen };
}

// Obviously fake, lowercase-only values: the IP and the user id of the log lines are keyed with them.
const FAKE_ENV = {
  APP_ORIGIN: 'http://localhost:3000',
  SUPABASE_URL: 'http://127.0.0.1:54321',
  SUPABASE_PUBLISHABLE_KEY: 'fake-publishable-key-for-unit-tests',
  SUPABASE_SECRET_KEY: 'fake-secret-key-for-unit-tests',
  RATE_LIMIT_KEY_SECRET: 'unit-test-only-rate-limit-key-not-a-real-value',
};

beforeEach(() => {
  for (const [name, value] of Object.entries(FAKE_ENV)) vi.stubEnv(name, value);
  gatewayOptions.length = 0;
  gateway = createFakePasswordGateway(TEMPORARY);
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

function pipeline(
  principal = client(['CHANGE_PASSWORD']),
  rateLimiter: RateLimiter = limiterDenying(() => false).limiter,
) {
  const { withRoute, logs, principalResolver } = createTestPipeline({ principal, rateLimiter });
  return { handler: createChangePasswordHandler(withRoute), logs, principalResolver };
}

describe('POST /auth/password: the policy of the contract', () => {
  it('SEC-01: is not reachable without a session (401), and nothing is checked', async () => {
    // a pipeline whose resolver finds no principal
    const { withRoute } = createTestPipeline({ principal: null });
    const response = await createChangePasswordHandler(withRoute)(
      request({ currentPassword: TEMPORARY, newPassword: FRESH }),
    );
    expect(response.status).toBe(401);
    expect(gatewayOptions).toEqual([]);
  });

  it('AC-05: is reachable with CHANGE_PASSWORD pending, and so is it with ENROLL_MFA (a CEO of first access)', async () => {
    for (const principal of [
      client(['CHANGE_PASSWORD']),
      principalFixture({ aal: 'aal1', pendingActions: ['CHANGE_PASSWORD', 'ENROLL_MFA'] }),
      principalFixture({ aal: 'aal1', pendingActions: ['ENROLL_MFA'] }),
      client(),
    ]) {
      gateway = createFakePasswordGateway(TEMPORARY);
      const { handler } = pipeline(principal);
      const response = await handler(request({ currentPassword: TEMPORARY, newPassword: FRESH }));
      expect(response.status, JSON.stringify(principal.pendingActions)).toBe(204);
    }
  });

  it('a CEO with a verified second factor and an aal1 session is 403 MFA_VERIFICATION_REQUIRED, before anything else', async () => {
    const { handler } = pipeline(principalFixture({ aal: 'aal1', pendingActions: ['VERIFY_MFA'] }));

    const response = await handler(request({ currentPassword: TEMPORARY, newPassword: FRESH }));

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'MFA_VERIFICATION_REQUIRED' });
    expect(gatewayOptions).toEqual([]);
  });

  it('x-rate-limit: counts every request in the `user:password-change` counter, 5 per 900 s, per user', async () => {
    const { limiter, seen } = limiterDenying(() => false);
    const { handler } = pipeline(client(['CHANGE_PASSWORD']), limiter);

    await handler(request({ currentPassword: TEMPORARY, newPassword: 'too-short' }));

    const entry = seen.find(({ key }) => key.bucket === 'user:password-change');
    expect(entry).toMatchObject({
      key: { scope: 'user', group: 'password-change', subject: client().userId },
      limit: 5,
      windowSeconds: 900,
    });
  });

  it('x-rate-limit: over the limit the answer is 429 with Retry-After, and nothing is checked', async () => {
    const { limiter } = limiterDenying((key) => key.group === 'password-change');
    const { handler } = pipeline(client(['CHANGE_PASSWORD']), limiter);

    const response = await handler(request({ currentPassword: TEMPORARY, newPassword: FRESH }));

    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('77');
    expect(gatewayOptions).toEqual([]);
  });

  it('ORIGIN: a request from another origin is 403 ORIGIN_NOT_ALLOWED', async () => {
    const { handler } = pipeline();
    const response = await handler(
      request({ currentPassword: TEMPORARY, newPassword: FRESH }, { origin: 'https://evil.test' }),
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ code: 'ORIGIN_NOT_ALLOWED' });
  });
});

describe('POST /auth/password: the outcomes', () => {
  it('AC-06: 204 with no body and no cookie when the change is done (the pipeline jar is untouched here)', async () => {
    const { handler, logs } = pipeline();

    const response = await handler(request({ currentPassword: TEMPORARY, newPassword: FRESH }));

    expect(response.status).toBe(204);
    expect(await response.text()).toBe('');
    expect(response.headers.getSetCookie()).toEqual([]);
    expect(logs.events('auth.password_changed')).toHaveLength(1);
    expect(logs.events('auth.password_changed')[0]).toMatchObject({
      userId: client().userId,
      level: 'info',
    });
  });

  it('E-12: a weak new password is 422 WEAK_PASSWORD (not 400), and the log has its code and no password', async () => {
    const { handler, logs } = pipeline();

    const response = await handler(request({ currentPassword: TEMPORARY, newPassword: 'short' }));

    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({ code: 'WEAK_PASSWORD', status: 422 });
    expect(logs.events('auth.password_change.failed')[0]).toMatchObject({
      reason: 'WEAK_PASSWORD',
      userId: client().userId,
    });
  });

  it('E-13: the same password is 422 PASSWORD_UNCHANGED', async () => {
    const { handler } = pipeline();
    const response = await handler(request({ currentPassword: TEMPORARY, newPassword: TEMPORARY }));
    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({ code: 'PASSWORD_UNCHANGED' });
  });

  it('AC-06: a wrong current password is 422 INVALID_CURRENT_PASSWORD', async () => {
    const { handler } = pipeline();
    const response = await handler(
      request({ currentPassword: 'not-the-current-one', newPassword: FRESH }),
    );
    expect(response.status).toBe(422);
    expect(await response.json()).toMatchObject({ code: 'INVALID_CURRENT_PASSWORD' });
  });

  it('SEC-06: an unknown field is 400, and nothing is checked', async () => {
    const { handler } = pipeline();
    const response = await handler(
      request({ currentPassword: TEMPORARY, newPassword: FRESH, role: 'ceo' }),
    );
    expect(response.status).toBe(400);
    expect(await response.json()).toMatchObject({ code: 'VALIDATION_ERROR' });
    expect(gatewayOptions).toEqual([]);
  });

  it('SEC-16: no log line of any outcome carries a password', async () => {
    const outcomes = [
      { currentPassword: TEMPORARY, newPassword: FRESH },
      { currentPassword: TEMPORARY, newPassword: 'short' },
      { currentPassword: 'not-the-current-one', newPassword: FRESH },
      { currentPassword: TEMPORARY, newPassword: TEMPORARY },
    ];
    for (const body of outcomes) {
      gateway = createFakePasswordGateway(TEMPORARY);
      const { handler, logs } = pipeline();
      await handler(request(body));
      for (const line of logs.lines) {
        for (const password of [TEMPORARY, FRESH, 'not-the-current-one']) {
          expect(line).not.toContain(password);
        }
      }
    }
  });

  it('E-21: an outage of Auth is 503 and the log says so', async () => {
    gateway = {
      ...createFakePasswordGateway(TEMPORARY),
      verifyCurrentPassword: () => Promise.reject(new ServiceUnavailableError('auth down')),
    };
    const { handler, logs } = pipeline();

    const response = await handler(request({ currentPassword: TEMPORARY, newPassword: FRESH }));

    expect(response.status).toBe(503);
    expect(logs.events('auth.password_change.failed')[0]).toMatchObject({
      reason: 'upstream_unavailable',
    });
  });

  it('an Auth answer nobody expected is 503, and the log keeps its status and code', async () => {
    gateway = {
      ...createFakePasswordGateway(TEMPORARY),
      verifyCurrentPassword: () =>
        Promise.reject(
          new UnexpectedAuthAnswerError('unexpected', {
            status: 422,
            code: 'email_provider_disabled',
          }),
        ),
    };
    const { handler, logs } = pipeline();

    const response = await handler(request({ currentPassword: TEMPORARY, newPassword: FRESH }));

    expect(response.status).toBe(503);
    expect(logs.events('auth.password_change.failed')[0]).toMatchObject({
      reason: 'upstream_error',
      authStatus: 422,
      authCode: 'email_provider_disabled',
    });
  });

  it('a change that is half done is 503 with the way out in the detail, and an error-level event', async () => {
    const fake = createFakePasswordGateway(TEMPORARY);
    fake.failMarkTimes(5);
    gateway = fake;
    const { handler, logs } = pipeline();

    const response = await handler(request({ currentPassword: TEMPORARY, newPassword: FRESH }));

    expect(response.status).toBe(503);
    const body = (await response.json()) as { code: string; detail: string };
    expect(body.code).toBe('SERVICE_UNAVAILABLE');
    expect(body.detail).toContain('new password as the current password');
    expect(response.headers.get('retry-after')).not.toBeNull();
    expect(logs.events('auth.password_change.incomplete')).toHaveLength(1);
    expect(logs.events('auth.password_change.incomplete')[0]).toMatchObject({
      level: 'error',
      userId: client().userId,
    });
    // the password is new: the log says nothing else about it
    for (const line of logs.lines) expect(line).not.toContain(FRESH);
  });

  it('M4: an update that gets no answer is 503 with the guidance of both states, and its own error-level event', async () => {
    const fake = createFakePasswordGateway(TEMPORARY);
    fake.failUpdate({ applied: true });
    gateway = fake;
    const { handler, logs } = pipeline();

    const response = await handler(request({ currentPassword: TEMPORARY, newPassword: FRESH }));

    expect(response.status).toBe(503);
    const body = (await response.json()) as { code: string; detail: string };
    expect(body.code).toBe('SERVICE_UNAVAILABLE');
    expect(body.detail).toContain('may already have been changed');
    expect(body.detail).toContain('new password as the current password');
    expect(response.headers.get('retry-after')).not.toBeNull();
    expect(logs.events('auth.password_change.uncertain')).toHaveLength(1);
    expect(logs.events('auth.password_change.uncertain')[0]).toMatchObject({
      level: 'error',
      userId: client().userId,
    });
    expect(logs.events('auth.password_change.incomplete')).toEqual([]);
    for (const line of logs.lines) expect(line).not.toContain(FRESH);
  });

  it('F-44: when the first mark committed and only its answer was lost, the change is 204 and nothing is logged as a failure', async () => {
    const fake = createFakePasswordGateway(TEMPORARY);
    fake.loseNextMarkAnswer();
    gateway = fake;
    const { handler, logs } = pipeline();

    const response = await handler(request({ currentPassword: TEMPORARY, newPassword: FRESH }));

    expect(response.status).toBe(204);
    expect(fake.pending()).toBe(false);
    expect(logs.events('auth.password_changed')).toHaveLength(1);
    expect(logs.events('auth.password_change.failed')).toEqual([]);
    expect(logs.events('auth.password_change.incomplete')).toEqual([]);
  });
});

describe('POST /auth/password: the sign-in that proves the password is charged to the login budget (F-02)', () => {
  it('spends the global login budget once, right before the check of the current password', async () => {
    const { limiter, seen } = limiterDenying(() => false);
    const { handler } = pipeline(client(['CHANGE_PASSWORD']), limiter);

    const response = await handler(request({ currentPassword: TEMPORARY, newPassword: FRESH }));

    expect(response.status).toBe(204);
    const global = seen.filter(({ key }) => key.scope === 'global');
    expect(global).toHaveLength(1);
    expect(global[0]).toMatchObject({
      key: { scope: 'global', group: LOGIN_GLOBAL_BUDGET.group, subject: 'global' },
      limit: LOGIN_GLOBAL_BUDGET.limit,
      windowSeconds: LOGIN_GLOBAL_BUDGET.windowSeconds,
    });
    // after the per-user counter of the route
    expect(seen.map(({ key }) => key.bucket)).toEqual(['user:password-change', 'global:login']);
  });

  it('over the budget the answer is 429 with Retry-After, and the password is neither checked nor changed', async () => {
    const { limiter } = limiterDenying((key) => key.scope === 'global');
    const fake = createFakePasswordGateway(TEMPORARY);
    gateway = fake;
    const { handler } = pipeline(client(['CHANGE_PASSWORD']), limiter);

    const response = await handler(request({ currentPassword: TEMPORARY, newPassword: FRESH }));

    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('77');
    expect(await response.json()).toMatchObject({ code: 'RATE_LIMITED' });
    expect(fake.calls).toEqual([]);
    expect(fake.password()).toBe(TEMPORARY);
  });

  it('is NOT spent when a pure check already refused the request (weak or unchanged): no call to Auth', async () => {
    const { limiter, seen } = limiterDenying(() => false);
    const { handler } = pipeline(client(['CHANGE_PASSWORD']), limiter);

    await handler(request({ currentPassword: TEMPORARY, newPassword: 'short' }));
    await handler(request({ currentPassword: TEMPORARY, newPassword: TEMPORARY }));

    expect(seen.filter(({ key }) => key.scope === 'global')).toEqual([]);
  });

  it('E-22: a limiter that fails on the global budget denies with 503, and nothing is changed', async () => {
    const limiter: RateLimiter = {
      consume: (key) =>
        key.scope === 'global'
          ? Promise.reject(new Error('limiter down'))
          : Promise.resolve({ allowed: true }),
    };
    const fake = createFakePasswordGateway(TEMPORARY);
    gateway = fake;
    const { handler } = pipeline(client(['CHANGE_PASSWORD']), limiter);

    const response = await handler(request({ currentPassword: TEMPORARY, newPassword: FRESH }));

    expect(response.status).toBe(503);
    expect(fake.password()).toBe(TEMPORARY);
  });
});
