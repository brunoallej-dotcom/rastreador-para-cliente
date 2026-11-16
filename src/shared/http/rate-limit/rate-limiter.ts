/**
 * What the key of a rule is made of (spec §3.9). `ip`, `account` and `user` are what a route policy
 * may declare. `global` has ONE subject for the whole app (an aggregate budget, e.g. all logins
 * together); it exists only for programmatic budgets (`HandlerContext.consumeGlobalBudget`, or a
 * component of the pipeline) and is never accepted in a route policy. A handler can also spend a
 * `user` budget that is not in its policy (`HandlerContext.consumeUserBudget`).
 */
export type RateLimitScope = 'ip' | 'account' | 'user' | 'global';

/** The scopes a route policy may use. */
export type PolicyRateLimitScope = Exclude<RateLimitScope, 'global'>;

/** The one subject of every `global` budget. */
export const GLOBAL_SUBJECT = 'global';

/**
 * Named counter groups of spec §3.9. Two routes share a counter (per subject) exactly when their
 * rules have the same `scope` and the same `group`; a group is a decision made by a person, never
 * derived from numbers, so changing the limit of one route cannot silently merge or split another
 * route's counter.
 *
 * - `login`             POST /auth/login: by IP and by account
 * - `totp-enroll`       POST /auth/mfa/totp/enroll (contract: user 10 / 15 min)
 * - `totp-verify`       POST /auth/mfa/totp/verify (contract: user 5 / 5 min)
 * - `totp-verify-daily` not a route rule: the daily cap per user (20 / 86,400 s) that the verify
 *                       handler spends with `consumeUserBudget`, on top of the contract's rule,
 *                       against slow guessing of TOTP codes (F-22)
 * - `password-change`   POST /auth/password
 * - `client-user-admin` provision a client login and reset its password (share one budget)
 * - `writes`            every other authenticated write
 * - `reads`             every authenticated read
 * - `health`            GET /health
 * - `session-upstream`  not a route: the per-IP budget of requests whose session cookie would make
 *                       the server call the Auth server (see the Supabase principal resolver)
 *
 * All rules of one group MUST carry the same `limit` and `windowSeconds` (the same
 * `x-rate-limit` in the contract); the contract-guardian checks it.
 */
export const RATE_LIMIT_GROUPS = [
  'login',
  'totp-enroll',
  'totp-verify',
  'totp-verify-daily',
  'password-change',
  'client-user-admin',
  'writes',
  'reads',
  'health',
  'session-upstream',
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

/**
 * A rule a route policy may declare: equal to an `x-rate-limit` entry, with the `ip`, `account` or
 * `user` scope (never `global`).
 */
export type PolicyRateLimitRule = RateLimitRule & { readonly scope: PolicyRateLimitScope };

/** An aggregate budget (scope `global`): everything but the scope, which is implied. */
export type GlobalBudget = Omit<RateLimitRule, 'scope'>;

/**
 * A per-user budget a handler spends by itself (scope `user`, subject the user id), in addition to
 * the rules of its route policy: everything but the scope, which is implied.
 */
export type UserBudget = Omit<RateLimitRule, 'scope'>;

/** Identifies one counter. */
export type RateLimitKey = {
  readonly scope: RateLimitScope;
  readonly group: RateLimitGroup;
  /** `${scope}:${group}`, the name of the counter family, e.g. `user:writes`, `ip:login`. */
  readonly bucket: string;
  /**
   * PLAINTEXT subject: the client IP (an IPv6 address is already aggregated to its /64 prefix),
   * the normalized account identifier, the user id or, for `global`, the constant
   * `GLOBAL_SUBJECT`. The pipeline never hashes it. An
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

  /**
   * Is this counter ALREADY known to be denied, from what the limiter holds in memory? It never
   * counts a request, never calls a store and never throws, so it is free; `undefined` means "not
   * known to be denied", not "allowed". A limiter without such memory leaves it out. Callers use it
   * to refuse work early for a key that is over budget, as a second line behind `consume`.
   */
  peekDenial?(
    key: RateLimitKey,
    rule: RateLimitRule,
  ): { readonly retryAfterSeconds: number } | undefined;
}
