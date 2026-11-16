import { z } from 'zod';
import { getEnv } from '@/shared/config/env';
import { getAdminFacade } from '@/shared/db/admin-client';
import { hmacSubject } from './subject-hmac';
import type { RateLimitDecision, RateLimiter, RateLimitKey, RateLimitRule } from './rate-limiter';

export type RateLimitHitInput = {
  readonly bucket: string;
  readonly windowSeconds: number;
  readonly max: number;
};

/**
 * Calls `public.rate_limit_hit` and returns what it answered, unvalidated. Throws when the call
 * failed (the database is down, slow or refused). Injected so the limiter is testable without a
 * database.
 */
export type RateLimitHit = (input: RateLimitHitInput) => Promise<unknown>;

/** What `rate_limit_hit` returns: one row `{ allowed, retry_after_seconds }`. */
const hitResultSchema = z
  .array(
    z.object({
      allowed: z.boolean(),
      retry_after_seconds: z.number().int().min(0),
    }),
  )
  .length(1);

const MS_PER_SECOND = 1000;
/** Upper bound of remembered denials; past it, expired ones are swept and then the oldest go. */
export const DEFAULT_MAX_DENIALS = 10_000;

export type PostgresRateLimiterOptions = {
  /** HMAC key of the subjects. Default: `RATE_LIMIT_KEY_SECRET`. */
  readonly secret?: string;
  /** Default: the Postgres function through the admin facade. */
  readonly hit?: RateLimitHit;
  /** Milliseconds since the epoch. Default `Date.now`; tests inject their own. */
  readonly now?: () => number;
  /** Maximum number of remembered denials (default 10,000). */
  readonly maxDenials?: number;
};

/**
 * Rate limiter backed by the Postgres fixed-window counters (ADR 0004, spec §3.9).
 *
 * - The database never sees an IP, an e-mail or a user id: the counter is
 *   `<scope>:<group>:<HMAC-SHA256(RATE_LIMIT_KEY_SECRET, subject)>`.
 * - Any failure (the RPC throws, or answers something that is not exactly one well-formed row)
 *   throws: the pipeline turns it into 503 and never lets the request through (fail closed, E-22).
 * - `retryAfterSeconds` is at least 1, as the contract's `Retry-After` requires.
 * - A denial is remembered in this instance until the end of its window, and requests for the same
 *   counter are answered 429 from memory, without a database call. Otherwise a flood against one
 *   already-blocked subject would cost a database write per request, turning the limiter into an
 *   amplifier of the load it exists to stop. The memory is per instance and can only make the
 *   limit STRICTER (it denies, never allows), so it does not weaken the fail-closed behavior: the
 *   database remains the authority for every request that is not already denied.
 */
export function createPostgresRateLimiter(options: PostgresRateLimiterOptions = {}): RateLimiter {
  const secret = options.secret ?? getEnv().RATE_LIMIT_KEY_SECRET;
  const hit = options.hit ?? ((input: RateLimitHitInput) => getAdminFacade().rateLimitHit(input));
  const now = options.now ?? Date.now;
  const maxDenials = options.maxDenials ?? DEFAULT_MAX_DENIALS;

  /** counter id → when the denial ends (ms). A Map iterates in insertion order: oldest first. */
  const denials = new Map<string, number>();

  const remember = (id: string, untilMs: number, nowMs: number) => {
    denials.delete(id);
    if (denials.size >= maxDenials) {
      for (const [other, until] of denials) {
        if (until <= nowMs) denials.delete(other);
      }
      for (const oldest of denials.keys()) {
        if (denials.size < maxDenials) break;
        denials.delete(oldest);
      }
    }
    denials.set(id, untilMs);
  };

  return {
    async consume(key: RateLimitKey, rule: RateLimitRule): Promise<RateLimitDecision> {
      const bucket = `${key.bucket}:${hmacSubject(secret, key.subject)}`;
      // The window is part of the database key, so it is part of the memory's key too.
      const id = `${bucket}|${rule.windowSeconds}|${rule.limit}`;

      const nowMs = now();
      const blockedUntil = denials.get(id);
      if (blockedUntil !== undefined) {
        if (blockedUntil > nowMs) {
          return {
            allowed: false,
            retryAfterSeconds: Math.max(1, Math.ceil((blockedUntil - nowMs) / MS_PER_SECOND)),
          };
        }
        denials.delete(id);
      }

      const raw = await hit({ bucket, windowSeconds: rule.windowSeconds, max: rule.limit });

      const result = hitResultSchema.safeParse(raw);
      if (!result.success) throw new Error('rate_limit_hit returned an unexpected result');

      const [row] = result.data;
      if (row === undefined) throw new Error('rate_limit_hit returned no row');
      if (row.allowed) return { allowed: true };

      const retryAfterSeconds = Math.max(1, row.retry_after_seconds);
      remember(id, nowMs + retryAfterSeconds * MS_PER_SECOND, nowMs);
      return { allowed: false, retryAfterSeconds };
    },
  };
}
