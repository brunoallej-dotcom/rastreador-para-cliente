import type {
  RateLimitDecision,
  RateLimiter,
  RateLimitGroup,
  RateLimitKey,
  RateLimitRule,
} from './rate-limiter';

export type GroupRoutedRateLimiterOptions = {
  /** Groups that go to their own limiter. */
  readonly routes: Readonly<Partial<Record<RateLimitGroup, RateLimiter>>>;
  /** Every other group. */
  readonly fallback: RateLimiter;
};

/**
 * Sends each counter to a limiter by its `group`. Production wiring uses it to keep `health` on an
 * in-memory limiter and everything else on the Postgres one: `GET /health` documents no 503, so a
 * database outage must not be able to turn a liveness probe into an undocumented 503.
 */
export function createGroupRoutedRateLimiter(options: GroupRoutedRateLimiterOptions): RateLimiter {
  const limiterFor = (key: RateLimitKey): RateLimiter =>
    options.routes[key.group] ?? options.fallback;
  return {
    consume(key: RateLimitKey, rule: RateLimitRule): Promise<RateLimitDecision> {
      return limiterFor(key).consume(key, rule);
    },
    peekDenial(key: RateLimitKey, rule: RateLimitRule) {
      return limiterFor(key).peekDenial?.(key, rule);
    },
  };
}
