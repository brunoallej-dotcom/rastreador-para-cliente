import { afterEach, describe, expect, it, vi } from 'vitest';
import { startResponseFloor, timing } from './response-floor';

/** Replaces the clock: `elapse(ms)` moves it, `sleep` only records what was asked. */
function fakeClock(random = 0) {
  let nowMs = 1_000;
  const sleeps: number[] = [];
  vi.spyOn(timing, 'now').mockImplementation(() => nowMs);
  vi.spyOn(timing, 'random').mockImplementation(() => random);
  vi.spyOn(timing, 'sleep').mockImplementation((ms) => {
    sleeps.push(ms);
    nowMs += ms;
    return Promise.resolve();
  });
  return { sleeps, elapse: (ms: number) => void (nowMs += ms) };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('startResponseFloor (F-05)', () => {
  it('waits for the whole floor when the work was instant', async () => {
    const clock = fakeClock();
    const floor = startResponseFloor(400, 100);

    await floor.wait();

    expect(clock.sleeps).toEqual([400]);
  });

  it('waits only for what is left of the floor, measured from the moment it was started', async () => {
    const clock = fakeClock();
    const floor = startResponseFloor(400, 100);
    clock.elapse(150);

    await floor.wait();

    expect(clock.sleeps).toEqual([250]);
  });

  it('never adds time to an answer that was already slower than the floor', async () => {
    const clock = fakeClock();
    const floor = startResponseFloor(400, 100);
    clock.elapse(700);

    await floor.wait();

    expect(clock.sleeps).toEqual([]);
  });

  it('adds a random share of the jitter on top of the floor', async () => {
    const low = fakeClock(0);
    await startResponseFloor(400, 100).wait();
    expect(low.sleeps).toEqual([400]);
    vi.restoreAllMocks();

    const high = fakeClock(0.999);
    await startResponseFloor(400, 100).wait();
    expect(high.sleeps[0]).toBeCloseTo(499.9, 5);
    vi.restoreAllMocks();

    const middle = fakeClock(0.5);
    await startResponseFloor(400, 100).wait();
    expect(middle.sleeps).toEqual([450]);
  });

  it('never waits more than floor + jitter, and never less than the floor', async () => {
    for (const random of [0, 0.25, 0.5, 0.75, 0.9999]) {
      const clock = fakeClock(random);
      await startResponseFloor(400, 100).wait();
      expect(clock.sleeps[0]).toBeGreaterThanOrEqual(400);
      expect(clock.sleeps[0]).toBeLessThan(500);
      vi.restoreAllMocks();
    }
  });

  it('rejects a nonsensical floor or jitter', () => {
    expect(() => startResponseFloor(-1, 0)).toThrow(RangeError);
    expect(() => startResponseFloor(0, -1)).toThrow(RangeError);
    expect(() => startResponseFloor(Number.NaN, 0)).toThrow(RangeError);
  });

  it('uses the real clock by default: a floor of a few milliseconds really waits', async () => {
    const startedAt = performance.now();
    await startResponseFloor(30, 0).wait();
    expect(performance.now() - startedAt).toBeGreaterThanOrEqual(25);
  });
});
