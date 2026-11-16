import { systemClock, type Clock } from '@/shared/kernel';
import type { RateLimitDecision, RateLimiter, RateLimitKey, RateLimitRule } from './rate-limiter';

const MS_PER_SECOND = 1000;
/** Upper bound of live counters; past it the oldest are evicted, so memory cannot grow unbounded. */
export const DEFAULT_MAX_COUNTERS = 10_000;

type Window = { count: number; resetAtMs: number };

export type InMemoryRateLimiterOptions = {
  readonly clock?: Clock;
  /** Maximum number of live counters (default 10,000). */
  readonly maxCounters?: number;
};

/**
 * Fixed-window limiter in process memory. It is the fake for unit tests and the default wiring
 * until Wave 3 plugs the Postgres limiter into `pipeline-deps.ts`. It is NOT shared across
 * serverless instances, so it is not a real limit in production.
 *
 * Memory is bounded: when the number of counters reaches `maxCounters`, expired ones are swept
 * and, if that is not enough, the oldest counters (first created) are evicted. Eviction forgets a
 * counter, which can only make the limiter more permissive for the evicted subject.
 */
export function createInMemoryRateLimiter(options: InMemoryRateLimiterOptions = {}): RateLimiter {
  const clock = options.clock ?? systemClock;
  const maxCounters = options.maxCounters ?? DEFAULT_MAX_COUNTERS;
  // A Map iterates in insertion order and counters are inserted when their window opens, so the
  // first entries are the oldest.
  const windows = new Map<string, Window>();

  const makeRoom = (nowMs: number) => {
    if (windows.size < maxCounters) return;
    for (const [id, window] of windows) {
      if (window.resetAtMs <= nowMs) windows.delete(id);
    }
    for (const id of windows.keys()) {
      if (windows.size < maxCounters) return;
      windows.delete(id);
    }
  };

  return {
    consume(key: RateLimitKey, rule: RateLimitRule): Promise<RateLimitDecision> {
      const nowMs = clock.now().getTime();
      const id = `${key.bucket}|${key.subject}`;

      let window = windows.get(id);
      if (window === undefined || window.resetAtMs <= nowMs) {
        windows.delete(id); // reinsert, so an expired counter that restarts counts as new
        makeRoom(nowMs);
        window = { count: 0, resetAtMs: nowMs + rule.windowSeconds * MS_PER_SECOND };
        windows.set(id, window);
      }

      window.count += 1;
      if (window.count <= rule.limit) return Promise.resolve({ allowed: true });
      const retryAfterSeconds = Math.max(1, Math.ceil((window.resetAtMs - nowMs) / MS_PER_SECOND));
      return Promise.resolve({ allowed: false, retryAfterSeconds });
    },
  };
}
