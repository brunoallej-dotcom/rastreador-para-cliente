import { describe, expect, it } from 'vitest';
import { createGroupRoutedRateLimiter } from './group-routed-rate-limiter';
import {
  createPostgresRateLimiter,
  createSupabaseRateLimitHit,
  type RateLimitHit,
  type RateLimitHitInput,
} from './postgres-rate-limiter';
import type { RateLimiter, RateLimitKey, RateLimitRule } from './rate-limiter';
import { hmacSubject } from './subject-hmac';

// An obviously fake, lowercase-only test value (the secret-detection hook rightly ignores it).
const HMAC_KEY = 'unit-test-only-hmac-key-not-a-real-value-at-all';
const HEX_64 = /^[0-9a-f]{64}$/;

const loginAccountRule: RateLimitRule = {
  scope: 'account',
  group: 'login',
  limit: 10,
  windowSeconds: 900,
};

const keyFor = (subject: string, rule: RateLimitRule = loginAccountRule): RateLimitKey => ({
  scope: rule.scope,
  group: rule.group,
  bucket: `${rule.scope}:${rule.group}`,
  subject,
});

const ALLOWED = [{ allowed: true, retry_after_seconds: 0 }];

/** A scripted `rate_limit_hit` that records what the database would receive. */
function fakeHit(answer: unknown) {
  const received: RateLimitHitInput[] = [];
  const hit: RateLimitHit = (input) => {
    received.push(input);
    return answer instanceof Error ? Promise.reject(answer) : Promise.resolve(answer);
  };
  return { hit, received };
}

describe('createPostgresRateLimiter: key derivation', () => {
  it('SEC-09: the bucket is `<scope>:<group>:<HMAC-SHA256 hex of the subject>`', async () => {
    const { hit, received } = fakeHit(ALLOWED);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit });

    await limiter.consume(keyFor('maria@cliente.test'), loginAccountRule);

    expect(received).toHaveLength(1);
    expect(received[0]?.bucket).toBe(
      `account:login:${hmacSubject(HMAC_KEY, 'maria@cliente.test')}`,
    );
    expect(received[0]?.bucket.split(':')[2]).toMatch(HEX_64);
    expect(received[0]).toMatchObject({ windowSeconds: 900, max: 10 });
  });

  it('never hands the database the subject, in any form', async () => {
    const { hit, received } = fakeHit(ALLOWED);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit });
    const ipRule: RateLimitRule = { scope: 'ip', group: 'login', limit: 20, windowSeconds: 900 };

    await limiter.consume(keyFor('203.0.113.7', ipRule), ipRule);
    await limiter.consume(keyFor('2001:db8:1:2::/64', ipRule), ipRule);
    await limiter.consume(keyFor('maria@cliente.test'), loginAccountRule);

    for (const { bucket } of received) {
      expect(bucket).not.toContain('203.0.113.7');
      expect(bucket).not.toContain('2001:db8');
      expect(bucket).not.toContain('maria');
      expect(bucket).not.toContain('@');
    }
  });

  it('gives the same subject the same bucket, and different subjects or keys different ones', async () => {
    const { hit, received } = fakeHit(ALLOWED);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit });
    const userRule: RateLimitRule = {
      scope: 'user',
      group: 'reads',
      limit: 300,
      windowSeconds: 60,
    };

    await limiter.consume(keyFor('same'), loginAccountRule);
    await limiter.consume(keyFor('same'), loginAccountRule);
    await limiter.consume(keyFor('other'), loginAccountRule);
    await limiter.consume(keyFor('same', userRule), userRule);

    const [first, second, other, otherFamily] = received.map(({ bucket }) => bucket);
    expect(first).toBe(second);
    expect(other).not.toBe(first);
    expect(otherFamily).not.toBe(first);
    expect(otherFamily?.startsWith('user:reads:')).toBe(true);
  });

  it('a different key gives a different bucket for the same subject', async () => {
    const one = fakeHit(ALLOWED);
    const two = fakeHit(ALLOWED);
    const first = createPostgresRateLimiter({ secret: HMAC_KEY, hit: one.hit });
    const rotated = createPostgresRateLimiter({ secret: `${HMAC_KEY}-rotated`, hit: two.hit });
    await first.consume(keyFor('x'), loginAccountRule);
    await rotated.consume(keyFor('x'), loginAccountRule);
    expect(one.received[0]?.bucket).not.toBe(two.received[0]?.bucket);
  });

  it('keeps every bucket within what rate_limit_hit accepts (<= 200 chars of [A-Za-z0-9:._-])', async () => {
    const { hit, received } = fakeHit(ALLOWED);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit });
    const rule: RateLimitRule = {
      scope: 'user',
      group: 'client-user-admin',
      limit: 20,
      windowSeconds: 3600,
    };
    await limiter.consume(keyFor('11111111-1111-4111-8111-111111111111', rule), rule);
    expect(received[0]?.bucket).toMatch(/^[A-Za-z0-9:._-]{1,200}$/);
  });
});

describe('createPostgresRateLimiter: decisions', () => {
  it('allows when the database says allowed', async () => {
    const { hit } = fakeHit(ALLOWED);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit });
    await expect(limiter.consume(keyFor('a'), loginAccountRule)).resolves.toEqual({
      allowed: true,
    });
  });

  it('AC-03: denies with the retry-after the database computed', async () => {
    const { hit } = fakeHit([{ allowed: false, retry_after_seconds: 421 }]);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit });
    await expect(limiter.consume(keyFor('a'), loginAccountRule)).resolves.toEqual({
      allowed: false,
      retryAfterSeconds: 421,
    });
  });

  it('never answers a retry-after below 1 second', async () => {
    const { hit } = fakeHit([{ allowed: false, retry_after_seconds: 0 }]);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit });
    await expect(limiter.consume(keyFor('a'), loginAccountRule)).resolves.toEqual({
      allowed: false,
      retryAfterSeconds: 1,
    });
  });
});

describe('createPostgresRateLimiter: failures throw, so the pipeline answers 503 (E-22)', () => {
  it('throws when the call to the database fails', async () => {
    const { hit } = fakeHit(new Error('connection refused'));
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit });
    await expect(limiter.consume(keyFor('a'), loginAccountRule)).rejects.toThrow(
      'connection refused',
    );
  });

  it.each([
    ['null', null],
    ['no rows', []],
    [
      'two rows',
      [
        { allowed: true, retry_after_seconds: 0 },
        { allowed: true, retry_after_seconds: 0 },
      ],
    ],
    ['a bare object instead of an array', { allowed: true, retry_after_seconds: 0 }],
    ['a row without allowed', [{ retry_after_seconds: 0 }]],
    ['allowed as a string', [{ allowed: 'true', retry_after_seconds: 0 }]],
    ['a negative retry-after', [{ allowed: false, retry_after_seconds: -1 }]],
    ['a fractional retry-after', [{ allowed: false, retry_after_seconds: 1.5 }]],
    ['a missing retry-after', [{ allowed: false }]],
  ])('never lets the request through on %s', async (_label, answer) => {
    const { hit } = fakeHit(answer);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit });
    await expect(limiter.consume(keyFor('a'), loginAccountRule)).rejects.toThrow(
      'rate_limit_hit returned an unexpected result',
    );
  });
});

describe('createSupabaseRateLimitHit', () => {
  const rpcReturning = (outcome: { data: unknown; error: unknown }) => {
    const calls: { name: string; args: unknown }[] = [];
    const admin = {
      rpc(name: string, args: unknown) {
        calls.push({ name, args });
        return Promise.resolve(outcome);
      },
    };
    return { admin: admin as unknown as Parameters<typeof createSupabaseRateLimitHit>[0], calls };
  };

  it('calls rate_limit_hit with the typed parameters and returns its data', async () => {
    const { admin, calls } = rpcReturning({ data: ALLOWED, error: null });
    const result = await createSupabaseRateLimitHit(admin)({
      bucket: 'ip:login:abc',
      windowSeconds: 900,
      max: 20,
    });
    expect(result).toBe(ALLOWED);
    expect(calls).toEqual([
      {
        name: 'rate_limit_hit',
        args: { p_bucket: 'ip:login:abc', p_window_seconds: 900, p_max: 20 },
      },
    ]);
  });

  it('throws when the RPC reports an error, without echoing it', async () => {
    const { admin } = rpcReturning({
      data: null,
      error: { message: 'internal detail', code: '57P01' },
    });
    const rejection = createSupabaseRateLimitHit(admin)({ bucket: 'b', windowSeconds: 1, max: 1 });
    await expect(rejection).rejects.toThrow('rate_limit_hit failed');
    await expect(rejection).rejects.not.toThrow('internal detail');
  });
});

describe('createGroupRoutedRateLimiter', () => {
  const recording = (name: string, seen: string[]): RateLimiter => ({
    consume: (key) => {
      seen.push(`${name}:${key.group}`);
      return Promise.resolve({ allowed: true });
    },
  });

  it('sends a routed group to its own limiter and every other group to the fallback', async () => {
    const seen: string[] = [];
    const limiter = createGroupRoutedRateLimiter({
      routes: { health: recording('memory', seen) },
      fallback: recording('postgres', seen),
    });
    const consume = (group: RateLimitRule['group']) =>
      limiter.consume(
        { scope: 'ip', group, bucket: `ip:${group}`, subject: 'x' },
        { scope: 'ip', group, limit: 1, windowSeconds: 60 },
      );

    await consume('health');
    await consume('login');
    await consume('reads');

    expect(seen).toEqual(['memory:health', 'postgres:login', 'postgres:reads']);
  });
});
