import { describe, expect, it } from 'vitest';
import { fixedClock, systemClock } from './clock';

describe('Clock', () => {
  it('fixedClock always returns the same instant', () => {
    const instant = new Date('2026-01-02T03:04:05.000Z');
    const clock = fixedClock(instant);
    expect(clock.now().toISOString()).toBe('2026-01-02T03:04:05.000Z');
    expect(clock.now().getTime()).toBe(clock.now().getTime());
  });

  it('fixedClock returns copies, so callers cannot mutate the clock', () => {
    const clock = fixedClock(new Date('2026-01-02T03:04:05.000Z'));
    clock.now().setUTCFullYear(1999);
    expect(clock.now().getUTCFullYear()).toBe(2026);
  });

  it('systemClock follows the wall clock', () => {
    const before = Date.now();
    const now = systemClock.now().getTime();
    expect(now).toBeGreaterThanOrEqual(before);
    expect(now).toBeLessThanOrEqual(Date.now());
  });
});
