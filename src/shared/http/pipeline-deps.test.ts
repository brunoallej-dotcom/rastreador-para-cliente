import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { RateLimitGroup, RateLimitKey, RateLimitRule } from './rate-limit/rate-limiter';

// The secret-key client is replaced, so the test can see what would reach the database.
const database = vi.hoisted(() => ({
  rateLimitHit: vi.fn(),
}));
vi.mock('@/shared/db/admin-client', () => ({
  getAdminFacade: () => ({ rateLimitHit: database.rateLimitHit }),
}));

const ALLOWED = [{ allowed: true, retry_after_seconds: 0 }];

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

// The first test pays the cold import of the whole pipeline graph (env, Supabase clients, rate
// limiter). With coverage instrumentation on a memory-tight machine that once took longer than the
// 5 s default (2026-11-17), so the suite gets room for the import, not for the assertions.
const COLD_IMPORT_TIMEOUT_MS = 30_000;

describe(
  'production wiring of the rate limiter (pipeline-deps)',
  { timeout: COLD_IMPORT_TIMEOUT_MS },
  () => {
    beforeEach(() => {
      vi.stubEnv('APP_ORIGIN', 'http://localhost:3000');
      vi.stubEnv('SUPABASE_URL', 'http://127.0.0.1:54321');
      vi.stubEnv('SUPABASE_PUBLISHABLE_KEY', 'fake-publishable-key-for-unit-tests');
      vi.stubEnv('SUPABASE_SECRET_KEY', 'fake-secret-key-for-unit-tests');
      vi.stubEnv('RATE_LIMIT_KEY_SECRET', 'unit-test-only-rate-limit-key-not-a-real-value');
      database.rateLimitHit.mockReset();
      database.rateLimitHit.mockResolvedValue(ALLOWED);
    });

    afterEach(() => {
      vi.unstubAllEnvs();
    });

    it('E-22: the `health` group never touches the database: it is counted in memory', async () => {
      const limiter = await productionLimiter();

      await expect(limiter.consume(keyFor('health'), ruleFor('health'))).resolves.toEqual({
        allowed: true,
      });

      expect(database.rateLimitHit).not.toHaveBeenCalled();
    });

    it('a database outage cannot turn the liveness probe into an undocumented 503', async () => {
      database.rateLimitHit.mockRejectedValue(new TypeError('fetch failed'));
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

      expect(database.rateLimitHit).toHaveBeenCalledTimes(3);
      const buckets = database.rateLimitHit.mock.calls.map(
        ([input]) => (input as { bucket: string }).bucket,
      );
      expect(buckets[0]).toMatch(/^ip:login:[0-9a-f]{64}$/);
      expect(buckets[1]).toMatch(/^ip:writes:[0-9a-f]{64}$/);
      expect(buckets[2]).toMatch(/^ip:reads:[0-9a-f]{64}$/);
      expect(buckets.join()).not.toContain('203.0.113.9');
    });

    it('E-22: a database outage fails the other groups closed (the pipeline answers 503)', async () => {
      database.rateLimitHit.mockRejectedValue(new TypeError('fetch failed'));
      const limiter = await productionLimiter();

      await expect(limiter.consume(keyFor('login'), ruleFor('login'))).rejects.toThrow();
    });
  },
);
