// The Postgres limiter against the real local database: `rate_limit_hit` through the secret key.
// The env (URL, keys, HMAC key) comes from the `int` project setup (local Supabase only).
import { randomUUID } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { getAdminFacade } from '@/shared/db/admin-client';
import {
  createPostgresRateLimiter,
  type RateLimitHit,
  type RateLimitHitInput,
} from './postgres-rate-limiter';
import type { RateLimitKey, RateLimitRule } from './rate-limiter';

const rule = (overrides: Partial<RateLimitRule> = {}): RateLimitRule => ({
  scope: 'account',
  group: 'login',
  limit: 3,
  windowSeconds: 900,
  ...overrides,
});

const keyFor = (subject: string, forRule: RateLimitRule = rule()): RateLimitKey => ({
  scope: forRule.scope,
  group: forRule.group,
  bucket: `${forRule.scope}:${forRule.group}`,
  subject,
});

/** The real RPC, remembering what the database was handed. */
function spiedLimiter() {
  const sent: RateLimitHitInput[] = [];
  const realHit: RateLimitHit = (input) => getAdminFacade().rateLimitHit(input);
  const hit: RateLimitHit = (input) => {
    sent.push(input);
    return realHit(input);
  };
  return { limiter: createPostgresRateLimiter({ hit }), sent };
}

describe('createPostgresRateLimiter against the local database', () => {
  it('AC-03: counts per bucket, allows up to the limit and then denies', async () => {
    const { limiter } = spiedLimiter();
    const subject = `int-${randomUUID()}`;

    const decisions = [];
    for (let n = 1; n <= 5; n += 1) {
      decisions.push(await limiter.consume(keyFor(subject), rule()));
    }

    expect(decisions.map((decision) => decision.allowed)).toEqual([true, true, true, false, false]);
  });

  it('AC-03: a denial carries a Retry-After of at least 1 second and at most the window', async () => {
    const { limiter } = spiedLimiter();
    const subject = `int-${randomUUID()}`;
    const oneShot = rule({ limit: 1, windowSeconds: 60 });

    await limiter.consume(keyFor(subject, oneShot), oneShot);
    const denied = await limiter.consume(keyFor(subject, oneShot), oneShot);

    expect(denied.allowed).toBe(false);
    if (denied.allowed) return;
    expect(Number.isInteger(denied.retryAfterSeconds)).toBe(true);
    expect(denied.retryAfterSeconds).toBeGreaterThanOrEqual(1);
    expect(denied.retryAfterSeconds).toBeLessThanOrEqual(60);
  });

  it('keeps subjects, scopes and groups apart', async () => {
    const { limiter } = spiedLimiter();
    const subject = `int-${randomUUID()}`;
    const oneShot = rule({ limit: 1 });
    const otherScope = rule({ limit: 1, scope: 'ip' });
    const otherGroup = rule({ limit: 1, scope: 'user', group: 'writes' });

    expect((await limiter.consume(keyFor(subject, oneShot), oneShot)).allowed).toBe(true);
    expect((await limiter.consume(keyFor(subject, oneShot), oneShot)).allowed).toBe(false);

    expect((await limiter.consume(keyFor(`${subject}-b`, oneShot), oneShot)).allowed).toBe(true);
    expect((await limiter.consume(keyFor(subject, otherScope), otherScope)).allowed).toBe(true);
    expect((await limiter.consume(keyFor(subject, otherGroup), otherGroup)).allowed).toBe(true);
  });

  it('never stores the raw subject: the database only receives <scope>:<group>:<64 hex>', async () => {
    const { limiter, sent } = spiedLimiter();
    const email = `person-${randomUUID()}@cliente.test`;
    const ip = '2001:db8:aaaa:bbbb::/64';
    const ipRule = rule({ scope: 'ip', limit: 5 });

    await limiter.consume(keyFor(email), rule());
    await limiter.consume(keyFor(ip, ipRule), ipRule);

    expect(sent).toHaveLength(2);
    for (const { bucket } of sent) {
      expect(bucket).toMatch(/^(account|ip):login:[0-9a-f]{64}$/);
      expect(bucket).not.toContain(email);
      expect(bucket).not.toContain('person-');
      expect(bucket).not.toContain('2001:db8');
    }
  });

  it('fails closed (throws) when the database refuses the call, instead of allowing', async () => {
    const limiter = createPostgresRateLimiter({
      // the database rejects a window of zero seconds (INVALID_INPUT)
      hit: (input) => getAdminFacade().rateLimitHit({ ...input, windowSeconds: 0 }),
    });
    await expect(limiter.consume(keyFor(`int-${randomUUID()}`), rule())).rejects.toThrow(
      'rate_limit_hit failed',
    );
  });
});
