import { describe, expect, it } from 'vitest';
import type { Clock } from '@/shared/kernel';
import { createInMemoryRateLimiter } from './in-memory-rate-limiter';
import type { RateLimitKey, RateLimitRule } from './rate-limiter';

const rule: RateLimitRule = { scope: 'ip', group: 'session-upstream', limit: 2, windowSeconds: 60 };
const keyFor = (subject: string): RateLimitKey => ({
  scope: rule.scope,
  group: rule.group,
  bucket: 'ip:session-upstream',
  subject,
});

function handClock(startMs = Date.parse('2026-11-16T12:00:00Z')) {
  let nowMs = startMs;
  const clock: Clock = { now: () => new Date(nowMs) };
  return { clock, advance: (ms: number) => void (nowMs += ms) };
}

describe('createInMemoryRateLimiter: peekDenial (F-01)', () => {
  it('is undefined for a counter that is within its limit, or that does not exist', async () => {
    const limiter = createInMemoryRateLimiter();
    expect(limiter.peekDenial?.(keyFor('a'), rule)).toBeUndefined();

    await limiter.consume(keyFor('a'), rule);
    await limiter.consume(keyFor('a'), rule); // the limit itself is still allowed
    expect(limiter.peekDenial?.(keyFor('a'), rule)).toBeUndefined();
  });

  it('answers once the counter is past its limit, with the time left, and never counts', async () => {
    const time = handClock();
    const limiter = createInMemoryRateLimiter({ clock: time.clock });
    for (let n = 0; n < 3; n += 1) await limiter.consume(keyFor('a'), rule);

    time.advance(15_000);
    expect(limiter.peekDenial?.(keyFor('a'), rule)).toEqual({ retryAfterSeconds: 45 });
    // peeking any number of times changes nothing: after the window the counter starts again
    for (let n = 0; n < 10; n += 1) limiter.peekDenial?.(keyFor('a'), rule);
    time.advance(45_000);
    expect(limiter.peekDenial?.(keyFor('a'), rule)).toBeUndefined();
    await expect(limiter.consume(keyFor('a'), rule)).resolves.toEqual({ allowed: true });
  });

  it('is per subject', async () => {
    const limiter = createInMemoryRateLimiter();
    for (let n = 0; n < 3; n += 1) await limiter.consume(keyFor('a'), rule);

    expect(limiter.peekDenial?.(keyFor('a'), rule)).toBeDefined();
    expect(limiter.peekDenial?.(keyFor('b'), rule)).toBeUndefined();
  });
});
