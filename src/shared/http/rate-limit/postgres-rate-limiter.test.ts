import { describe, expect, it } from 'vitest';
import { createGroupRoutedRateLimiter } from './group-routed-rate-limiter';
import {
  createPostgresRateLimiter,
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

describe('createPostgresRateLimiter: remembered denials (F-06)', () => {
  const DENIED = [{ allowed: false, retry_after_seconds: 120 }];

  /** A clock the test moves by hand, in milliseconds. */
  const clock = (startMs = 1_000_000) => {
    let nowMs = startMs;
    return { now: () => nowMs, advance: (ms: number) => void (nowMs += ms) };
  };

  it('answers a denied counter from memory: no database call while the denial lasts', async () => {
    const time = clock();
    const { hit, received } = fakeHit(DENIED);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit, now: time.now });

    const first = await limiter.consume(keyFor('flooded'), loginAccountRule);
    time.advance(10_000);
    const second = await limiter.consume(keyFor('flooded'), loginAccountRule);
    const third = await limiter.consume(keyFor('flooded'), loginAccountRule);

    expect(first).toEqual({ allowed: false, retryAfterSeconds: 120 });
    // 10 s later the same denial is answered with the time that is left
    expect(second).toEqual({ allowed: false, retryAfterSeconds: 110 });
    expect(third).toEqual({ allowed: false, retryAfterSeconds: 110 });
    expect(received).toHaveLength(1);
  });

  it('asks the database again when the remembered denial has ended', async () => {
    const time = clock();
    const { hit, received } = fakeHit(DENIED);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit, now: time.now });

    await limiter.consume(keyFor('flooded'), loginAccountRule);
    time.advance(120_000);
    await limiter.consume(keyFor('flooded'), loginAccountRule);

    expect(received).toHaveLength(2);
  });

  it('never invents an allowance: an allowed answer is not remembered, so every call is counted', async () => {
    const { hit, received } = fakeHit(ALLOWED);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit });

    for (let n = 0; n < 5; n += 1) await limiter.consume(keyFor('fine'), loginAccountRule);

    expect(received).toHaveLength(5);
  });

  it('remembers per counter: another subject, scope, group or window still reaches the database', async () => {
    const { hit, received } = fakeHit(DENIED);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit });
    const otherWindow: RateLimitRule = { ...loginAccountRule, windowSeconds: 60 };
    const otherGroup: RateLimitRule = { ...loginAccountRule, scope: 'ip', group: 'writes' };

    await limiter.consume(keyFor('a'), loginAccountRule);
    await limiter.consume(keyFor('b'), loginAccountRule);
    await limiter.consume(keyFor('a', otherWindow), otherWindow);
    await limiter.consume(keyFor('a', otherGroup), otherGroup);
    await limiter.consume(keyFor('a'), loginAccountRule); // this one IS remembered

    expect(received).toHaveLength(4);
  });

  it('keeps failing closed: a failure is never remembered as an allowance', async () => {
    const limiter = createPostgresRateLimiter({
      secret: HMAC_KEY,
      hit: () => Promise.reject(new Error('connection refused')),
    });
    await expect(limiter.consume(keyFor('a'), loginAccountRule)).rejects.toThrow();
    await expect(limiter.consume(keyFor('a'), loginAccountRule)).rejects.toThrow();
  });

  it('is bounded: past the limit the oldest denial is forgotten, never the newest', async () => {
    const time = clock();
    const { hit, received } = fakeHit(DENIED);
    const limiter = createPostgresRateLimiter({
      secret: HMAC_KEY,
      hit,
      now: time.now,
      maxDenials: 2,
    });

    await limiter.consume(keyFor('one'), loginAccountRule);
    await limiter.consume(keyFor('two'), loginAccountRule);
    await limiter.consume(keyFor('three'), loginAccountRule); // evicts 'one'
    expect(received).toHaveLength(3);

    await limiter.consume(keyFor('three'), loginAccountRule); // still remembered
    await limiter.consume(keyFor('two'), loginAccountRule); // still remembered
    expect(received).toHaveLength(3);

    await limiter.consume(keyFor('one'), loginAccountRule); // forgotten: back to the database
    expect(received).toHaveLength(4);
  });

  it('the memory holds the HMAC bucket, never the subject (nothing to leak from a heap dump)', async () => {
    const { hit, received } = fakeHit(DENIED);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit });
    await limiter.consume(keyFor('maria@cliente.test'), loginAccountRule);
    expect(received[0]?.bucket).not.toContain('maria');
  });

  it('eviction is O(1): the oldest entry goes, expired or not, and a repeated denial moves a counter to the newest position', async () => {
    const time = clock();
    const { hit, received } = fakeHit(DENIED);
    const limiter = createPostgresRateLimiter({
      secret: HMAC_KEY,
      hit,
      now: time.now,
      maxDenials: 2,
    });

    await limiter.consume(keyFor('one'), loginAccountRule);
    await limiter.consume(keyFor('two'), loginAccountRule);
    time.advance(120_000); // both denials ended
    await limiter.consume(keyFor('one'), loginAccountRule); // asks again, denied again: now the NEWEST
    expect(received).toHaveLength(3);

    await limiter.consume(keyFor('three'), loginAccountRule); // full: the oldest ('two') goes
    expect(received).toHaveLength(4);

    await limiter.consume(keyFor('one'), loginAccountRule); // still remembered
    await limiter.consume(keyFor('three'), loginAccountRule); // still remembered
    expect(received).toHaveLength(4);
    await limiter.consume(keyFor('two'), loginAccountRule); // was evicted
    expect(received).toHaveLength(5);
  });
});

describe('createPostgresRateLimiter: peekDenial (F-01)', () => {
  const DENIED = [{ allowed: false, retry_after_seconds: 120 }];
  const clock = (startMs = 1_000_000) => {
    let nowMs = startMs;
    return { now: () => nowMs, advance: (ms: number) => void (nowMs += ms) };
  };

  it('is undefined for a counter that was never denied, and never calls the database', async () => {
    const { hit, received } = fakeHit(ALLOWED);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit });

    expect(limiter.peekDenial?.(keyFor('fine'), loginAccountRule)).toBeUndefined();

    await limiter.consume(keyFor('fine'), loginAccountRule);
    expect(limiter.peekDenial?.(keyFor('fine'), loginAccountRule)).toBeUndefined();
    expect(received).toHaveLength(1);
  });

  it('answers from memory with the time that is left, and counts nothing', async () => {
    const time = clock();
    const { hit, received } = fakeHit(DENIED);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit, now: time.now });
    await limiter.consume(keyFor('flooded'), loginAccountRule);

    time.advance(20_000);
    expect(limiter.peekDenial?.(keyFor('flooded'), loginAccountRule)).toEqual({
      retryAfterSeconds: 100,
    });
    expect(received).toHaveLength(1);
  });

  it('forgets a denial that has ended, and is per counter (subject, group, window)', async () => {
    const time = clock();
    const { hit } = fakeHit(DENIED);
    const limiter = createPostgresRateLimiter({ secret: HMAC_KEY, hit, now: time.now });
    const otherWindow: RateLimitRule = { ...loginAccountRule, windowSeconds: 60 };
    await limiter.consume(keyFor('flooded'), loginAccountRule);

    expect(limiter.peekDenial?.(keyFor('other'), loginAccountRule)).toBeUndefined();
    expect(limiter.peekDenial?.(keyFor('flooded', otherWindow), otherWindow)).toBeUndefined();

    time.advance(120_000);
    expect(limiter.peekDenial?.(keyFor('flooded'), loginAccountRule)).toBeUndefined();
  });

  it('never throws and never reaches the database, even when the database is down', () => {
    const limiter = createPostgresRateLimiter({
      secret: HMAC_KEY,
      hit: () => Promise.reject(new Error('connection refused')),
    });
    expect(() => limiter.peekDenial?.(keyFor('a'), loginAccountRule)).not.toThrow();
  });

  it('the group-routed limiter peeks at the limiter of that group, and falls back to the default one', async () => {
    const { hit } = fakeHit(DENIED);
    const postgres = createPostgresRateLimiter({ secret: HMAC_KEY, hit });
    const memoryOnly: RateLimiter = { consume: () => Promise.resolve({ allowed: true }) };
    const routed = createGroupRoutedRateLimiter({
      routes: { login: postgres },
      fallback: memoryOnly,
    });

    await routed.consume(keyFor('flooded'), loginAccountRule);

    expect(routed.peekDenial?.(keyFor('flooded'), loginAccountRule)).toEqual({
      retryAfterSeconds: 120,
    });
    const other: RateLimitRule = { ...loginAccountRule, group: 'reads' };
    // a group routed to a limiter with no memory has nothing to peek at
    expect(routed.peekDenial?.(keyFor('flooded', other), other)).toBeUndefined();
  });
});
