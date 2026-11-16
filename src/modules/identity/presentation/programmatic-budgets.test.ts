// The programmatic budgets (`PROGRAMMATIC_BUDGETS`) against the handlers and the source: the half of
// the two-way check that the contract test (`tests/contract/contract-invariants.test.ts`) cannot do.
//   registry -> handlers: every operation the registry names really spends its budget, once;
//   source -> registry:   no `consume(Global|User)Budget(` call in `src/` spends anything else.
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { PasswordGateway } from '../domain/password-ports';
import { createFakePasswordGateway } from '../application/password-fakes';
import type { PasswordGatewayOptions } from '../infrastructure/supabase-password-gateway';
import type {
  RateLimitDecision,
  RateLimiter,
  RateLimitKey,
  RateLimitRule,
} from '@/shared/http/rate-limit/rate-limiter';
import { apiRequest, createTestPipeline, principalFixture } from '@/shared/http/testing';
import { createChangePasswordHandler } from './change-password.handler';
import { createLoginHandler } from './login.handler';
import { PROGRAMMATIC_BUDGETS } from './rate-limit-budgets';
import { createVerifyTotpHandler } from './verify-totp.handler';

// The edge (Supabase) is replaced: the password gateway by the in-memory fake, wired the way the
// real one is (the budget hook runs right before the check of the current password). The handlers,
// the pipeline, the schemas and the use cases are the real code. A handler that did NOT spend its
// budget would go on to these stand-ins and fail the 429 assertion below, not reach anything real.
let gateway: PasswordGateway;

vi.mock('../infrastructure/supabase-password-gateway', () => ({
  createSupabasePasswordGateway: (_supabase: unknown, options: PasswordGatewayOptions) =>
    ({
      async verifyCurrentPassword(password: string) {
        await options.beforeReauthentication?.();
        return gateway.verifyCurrentPassword(password);
      },
      updatePassword: (change: Parameters<PasswordGateway['updatePassword']>[0]) =>
        gateway.updatePassword(change),
      markPasswordChanged: () => gateway.markPasswordChanged(),
    }) satisfies PasswordGateway,
}));
vi.mock('../infrastructure/reauth-client', () => ({ createReauthClient: () => ({}) }));
vi.mock('@/shared/db/server-client', () => ({ getRequestSupabase: () => ({}) }));

// Obviously fake, lowercase-only values (the secret-detection hook rightly ignores them).
const FAKE_ENV = {
  APP_ORIGIN: 'http://localhost:3000',
  SUPABASE_URL: 'http://127.0.0.1:54321',
  SUPABASE_PUBLISHABLE_KEY: 'fake-publishable-key-for-unit-tests',
  SUPABASE_SECRET_KEY: 'fake-secret-key-for-unit-tests',
  RATE_LIMIT_KEY_SECRET: 'unit-test-only-rate-limit-key-not-a-real-value',
};

const USER_ID = '11111111-1111-4111-8111-111111111111';
const IP = { 'x-real-ip': '203.0.113.9' };
const RETRY_AFTER_SECONDS = 77;

beforeEach(() => {
  for (const [name, value] of Object.entries(FAKE_ENV)) vi.stubEnv(name, value);
  gateway = createFakePasswordGateway('Temporary-Pass-1234');
  // an Auth server or database that must not be reached: the budget decides before
  vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('no outbound call expected'));
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

type Consumption = { key: RateLimitKey; rule: RateLimitRule };

/** Records every consumption; refuses the ones `deny` picks. */
function limiterDenying(deny: (key: RateLimitKey) => boolean) {
  const seen: Consumption[] = [];
  const limiter: RateLimiter = {
    consume(key, rule): Promise<RateLimitDecision> {
      seen.push({ key, rule });
      return Promise.resolve(
        deny(key) ? { allowed: false, retryAfterSeconds: RETRY_AFTER_SECONDS } : { allowed: true },
      );
    },
  };
  return { limiter, seen };
}

/** One driver per operation of the registry: it calls the REAL handler with the given limiter. */
const drivers: Record<string, (limiter: RateLimiter) => Promise<Response>> = {
  login: (rateLimiter) => {
    const { withRoute } = createTestPipeline({ rateLimiter });
    return createLoginHandler(withRoute)(
      apiRequest('/auth/login', {
        method: 'POST',
        json: { email: 'maria@cliente.test', password: 'any-password-1' },
        headers: IP,
      }),
    );
  },
  changePassword: (rateLimiter) => {
    const principal = principalFixture({
      role: 'client',
      clientId: '22222222-2222-4222-8222-222222222222',
      aal: 'aal1',
      pendingActions: ['CHANGE_PASSWORD'],
    });
    const { withRoute } = createTestPipeline({ principal, rateLimiter });
    return createChangePasswordHandler(withRoute)(
      apiRequest('/auth/password', {
        method: 'POST',
        // Low-entropy stand-ins built at run time: the limiter refuses before any password matters.
        json: { currentPassword: 'c'.repeat(16), newPassword: 'n'.repeat(16) },
        headers: IP,
      }),
    );
  },
  verifyTotp: (rateLimiter) => {
    const principal = principalFixture({
      userId: USER_ID,
      aal: 'aal1',
      pendingActions: ['VERIFY_MFA'],
    });
    const { withRoute } = createTestPipeline({ principal, rateLimiter });
    return createVerifyTotpHandler(withRoute)(
      apiRequest('/auth/mfa/totp/verify', {
        method: 'POST',
        json: { code: '123456' },
        headers: IP,
      }),
    );
  },
};

const spenders = Object.entries(PROGRAMMATIC_BUDGETS).flatMap(([name, entry]) =>
  entry.spentBy.map((operationId) => [name, operationId, entry] as const),
);

describe('the registry of programmatic budgets reaches the handlers', () => {
  it('has a driver for every operation it names, and for no other', () => {
    const named = new Set(spenders.map(([, operationId]) => operationId));
    expect(new Set(Object.keys(drivers))).toEqual(named);
  });

  it.each(spenders)(
    '%s is spent by %s: over budget the answer is 429, and the budget was consumed once with the numbers of the registry',
    async (_name, operationId, entry) => {
      const { scope, budget } = entry;
      const bucket = `${scope}:${budget.group}`;
      const { limiter, seen } = limiterDenying((key) => key.bucket === bucket);

      const response = await drivers[operationId]?.(limiter);

      expect(response?.status).toBe(429);
      expect(response?.headers.get('retry-after')).toBe(String(RETRY_AFTER_SECONDS));
      const spent = seen.filter(({ key }) => key.bucket === bucket);
      expect(spent).toHaveLength(1);
      expect(spent[0]).toMatchObject({
        key: {
          scope,
          group: budget.group,
          subject: scope === 'global' ? 'global' : USER_ID,
        },
        rule: {
          scope,
          group: budget.group,
          limit: budget.limit,
          windowSeconds: budget.windowSeconds,
        },
      });
      // the budget decided before anything reached the edge
      expect(globalThis.fetch).not.toHaveBeenCalled();
    },
  );
});

describe('the source spends no programmatic budget that is not in the registry', () => {
  const SOURCE = fileURLToPath(new URL('../../../', import.meta.url));
  const CALL = /\bconsume(Global|User)Budget\(/g;
  const CALL_WITH_NAME = /\bconsume(Global|User)Budget\(\s*([A-Za-z_$][\w$]*)\s*\)/g;

  const files = readdirSync(SOURCE, { recursive: true, encoding: 'utf8' })
    .filter((path) => path.endsWith('.ts') && !/\.(test|d)\.ts$/.test(path))
    .map((path) => ({ path, text: readFileSync(`${SOURCE}${path}`, 'utf8') }));

  const calls = files.flatMap(({ path, text }) =>
    [...text.matchAll(CALL_WITH_NAME)].map((match) => ({
      path,
      kind: match[1]?.toLowerCase(),
      name: match[2],
    })),
  );

  it('every call spends a named constant of the registry, with the kind of its scope', () => {
    const everyCall = files.reduce((sum, { text }) => sum + [...text.matchAll(CALL)].length, 0);
    // a call whose argument is anything but a bare name (an inline object, a variable) is not provable
    expect(calls).toHaveLength(everyCall);
    for (const { path, kind, name } of calls) {
      const entry =
        name === undefined
          ? undefined
          : Object.entries(PROGRAMMATIC_BUDGETS).find(([key]) => key === name)?.[1];
      expect(entry, `${path} spends ${name}, which is not in PROGRAMMATIC_BUDGETS`).toBeDefined();
      expect(entry?.scope, `${path}: ${name}`).toBe(kind);
    }
  });

  it('and there are exactly as many call sites as the registry says (a handler that dropped its spend, or a new one, fails here)', () => {
    const expected = Object.entries(PROGRAMMATIC_BUDGETS).flatMap(([name, entry]) =>
      entry.spentBy.map(() => name),
    );
    expect(calls.map(({ name }) => name).sort()).toEqual(expected.sort());
  });
});
