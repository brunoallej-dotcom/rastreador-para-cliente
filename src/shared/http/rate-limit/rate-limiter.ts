/** What the key of a rule is made of (spec §3.9). */
export type RateLimitScope = 'ip' | 'account' | 'user';

/**
 * Named counter groups of spec §3.9. Two routes share a counter (per subject) exactly when their
 * rules have the same `scope` and the same `group`; a group is a decision made by a person, never
 * derived from numbers, so changing the limit of one route cannot silently merge or split another
 * route's counter.
 *
 * - `login`             POST /auth/login: by IP and by account
 * - `totp-enroll`       POST /auth/mfa/totp/enroll (contract: user 10 / 15 min)
 * - `totp-verify`       POST /auth/mfa/totp/verify
 * - `password-change`   POST /auth/password
 * - `client-user-admin` provision a client login and reset its password (share one budget)
 * - `writes`            every other authenticated write
 * - `reads`             every authenticated read
 * - `health`            GET /health
 *
 * All rules of one group MUST carry the same `limit` and `windowSeconds` (the same
 * `x-rate-limit` in the contract); the contract-guardian checks it.
 */
export const RATE_LIMIT_GROUPS = [
  'login',
  'totp-enroll',
  'totp-verify',
  'password-change',
  'client-user-admin',
  'writes',
  'reads',
  'health',
] as const;

export type RateLimitGroup = (typeof RATE_LIMIT_GROUPS)[number];

/**
 * One limit of a route, declared in its policy and equal to the contract's `x-rate-limit`:
 * at most `limit` requests per `windowSeconds` for each subject, in the counter `scope:group`.
 */
export type RateLimitRule = {
  readonly scope: RateLimitScope;
  readonly group: RateLimitGroup;
  readonly limit: number;
  readonly windowSeconds: number;
};

/** Identifies one counter. */
export type RateLimitKey = {
  readonly scope: RateLimitScope;
  readonly group: RateLimitGroup;
  /** `${scope}:${group}`, the name of the counter family, e.g. `user:writes`, `ip:login`. */
  readonly bucket: string;
  /**
   * PLAINTEXT subject: the client IP (an IPv6 address is already aggregated to its /64 prefix),
   * the normalized account identifier or the user id. The pipeline never hashes it. An
   * implementation that PERSISTS counters (the Postgres limiter, Wave 3) must turn it into an
   * HMAC-SHA256 keyed with `RATE_LIMIT_KEY_SECRET` before storing it, so the database holds
   * neither IPs nor e-mails (spec §3.9). An in-memory implementation may use it as is.
   */
  readonly subject: string;
};

export type RateLimitDecision =
  { readonly allowed: true } | { readonly allowed: false; readonly retryAfterSeconds: number };

/**
 * Port of the rate limiter. `consume` counts one request against the key and says whether it may
 * proceed. It MUST be atomic per key. It may throw when its store is unavailable: the pipeline
 * then denies the request with 503 (fail closed, E-22), it never lets it through.
 */
export interface RateLimiter {
  consume(key: RateLimitKey, rule: RateLimitRule): Promise<RateLimitDecision>;
}
