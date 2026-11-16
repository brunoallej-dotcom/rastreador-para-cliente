/**
 * The clock of the response floor, replaceable in tests: `now` and `sleep` in milliseconds and the
 * source of the jitter. Production code reads these at call time (never captures them), so a test
 * can swap one with `vi.spyOn(timing, 'sleep')` and nothing waits for real.
 */
export const timing = {
  now: (): number => performance.now(),
  sleep: (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms)),
  random: (): number => Math.random(),
};

export type ResponseFloor = {
  /**
   * Resolves once at least `floorMs` plus a random share of `jitterMs` have passed since the floor
   * was started. If the work already took longer, it resolves at once: a floor never adds to a slow
   * answer, it only keeps a fast one from being faster than the slowest of its kind.
   */
  wait(): Promise<void>;
};

/**
 * Starts a response floor now (call it first thing in the handler). Used where the time an answer
 * takes would tell a caller something the answer itself hides: a refused login must take the same
 * time whether the e-mail is unknown, the password is wrong or the account is disabled (a disabled
 * account costs extra calls to the Auth server), or the timing enumerates accounts (F-05).
 *
 * The floor must sit above the slowest refused path of its kind; the jitter keeps the floor itself
 * from being a fingerprint.
 */
export function startResponseFloor(floorMs: number, jitterMs: number): ResponseFloor {
  if (!(floorMs >= 0) || !(jitterMs >= 0)) {
    throw new RangeError(`startResponseFloor: invalid floor ${floorMs} / jitter ${jitterMs}`);
  }
  const startedAt = timing.now();
  return {
    async wait() {
      const target = floorMs + timing.random() * jitterMs;
      const remaining = target - (timing.now() - startedAt);
      if (remaining > 0) await timing.sleep(remaining);
    },
  };
}
