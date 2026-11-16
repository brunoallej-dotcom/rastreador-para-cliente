import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { RateLimitGroup, RateLimitKey, RateLimitRule } from './rate-limit/rate-limiter';

// The secret-key client is replaced, so the test can see what would reach the database.
const database = vi.hoisted(() => ({
  rpc: vi.fn(),
}));
vi.mock('@/shared/db/admin-client', () => ({
  getAdminClient: () => ({ rpc: database.rpc }),
}));

const ALLOWED = { data: [{ allowed: true, retry_after_seconds: 0 }], error: null };

const keyFor = (group: RateLimitGroup): RateLimitKey => ({
  scope: 'ip',
  group,
  bucket: `ip:${group}`,
  subject: '203.0.113.9',
});
const ruleFor = (group: RateLimitGroup): RateLimitRule => ({
  scope: 'ip',
  group,
  limit: 1000,
  windowSeconds: 60,
});

async function productionLimiter() {
  // imported after the stubs: the wiring is built lazily, on first use
  const { getPipelineDeps } = await import('./pipeline-deps');
  return getPipelineDeps().rateLimiter;
}

describe('production wiring of the rate limiter (pipeline-deps)', () => {
  beforeEach(() => {
    vi.stubEnv('APP_ORIGIN', 'http://localhost:3000');
    vi.stubEnv('SUPABASE_URL', 'http://127.0.0.1:54321');
    vi.stubEnv('SUPABASE_PUBLISHABLE_KEY', 'fake-publishable-key-for-unit-tests');
    vi.stubEnv('SUPABASE_SECRET_KEY', 'fake-secret-key-for-unit-tests');
    vi.stubEnv('RATE_LIMIT_KEY_SECRET', 'unit-test-only-rate-limit-key-not-a-real-value');
    database.rpc.mockReset();
    database.rpc.mockResolvedValue(ALLOWED);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('E-22: the `health` group never touches the database: it is counted in memory', async () => {
    const limiter = await productionLimiter();

    await expect(limiter.consume(keyFor('health'), ruleFor('health'))).resolves.toEqual({
      allowed: true,
    });

    expect(database.rpc).not.toHaveBeenCalled();
  });

  it('a database outage cannot turn the liveness probe into an undocumented 503', async () => {
    database.rpc.mockRejectedValue(new TypeError('fetch failed'));
    const limiter = await productionLimiter();

    await expect(limiter.consume(keyFor('health'), ruleFor('health'))).resolves.toEqual({
      allowed: true,
    });
  });

  it('SEC-09: every other group goes to Postgres, keyed by an HMAC of the subject', async () => {
    const limiter = await productionLimiter();

    for (const group of ['login', 'writes', 'reads'] as const) {
      await limiter.consume(keyFor(group), ruleFor(group));
    }

    expect(database.rpc).toHaveBeenCalledTimes(3);
    const buckets = database.rpc.mock.calls.map(
      ([name, args]) => `${String(name)} ${(args as { p_bucket: string }).p_bucket}`,
    );
    expect(buckets[0]).toMatch(/^rate_limit_hit ip:login:[0-9a-f]{64}$/);
    expect(buckets[1]).toMatch(/^rate_limit_hit ip:writes:[0-9a-f]{64}$/);
    expect(buckets[2]).toMatch(/^rate_limit_hit ip:reads:[0-9a-f]{64}$/);
    expect(buckets.join()).not.toContain('203.0.113.9');
  });

  it('E-22: a database outage fails the other groups closed (the pipeline answers 503)', async () => {
    database.rpc.mockRejectedValue(new TypeError('fetch failed'));
    const limiter = await productionLimiter();

    await expect(limiter.consume(keyFor('login'), ruleFor('login'))).rejects.toThrow();
  });
});
