import { z } from 'zod';
import { getEnv } from '@/shared/config/env';
import { getAdminClient, type AdminSupabase } from '@/shared/db/admin-client';
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

/**
 * The `RateLimitHit` backed by the Postgres function, through the secret-key client. It is the
 * ONLY thing in the app that calls `rate_limit_hit` (only `service_role` may execute it).
 */
export function createSupabaseRateLimitHit(
  admin: Pick<AdminSupabase, 'rpc'> = getAdminClient(),
): RateLimitHit {
  return async ({ bucket, windowSeconds, max }) => {
    const { data, error } = await admin.rpc('rate_limit_hit', {
      p_bucket: bucket,
      p_window_seconds: windowSeconds,
      p_max: max,
    });
    if (error) throw new Error('rate_limit_hit failed', { cause: error });
    return data;
  };
}

export type PostgresRateLimiterOptions = {
  /** HMAC key of the subjects. Default: `RATE_LIMIT_KEY_SECRET`. */
  readonly secret?: string;
  /** Default: the Postgres function through the admin client. */
  readonly hit?: RateLimitHit;
};

/**
 * Rate limiter backed by the Postgres fixed-window counters (ADR 0004, spec §3.9).
 *
 * - The database never sees an IP, an e-mail or a user id: the counter is
 *   `<scope>:<group>:<HMAC-SHA256(RATE_LIMIT_KEY_SECRET, subject)>`.
 * - Any failure (the RPC throws, or answers something that is not exactly one well-formed row)
 *   throws: the pipeline turns it into 503 and never lets the request through (fail closed, E-22).
 * - `retryAfterSeconds` is at least 1, as the contract's `Retry-After` requires.
 */
export function createPostgresRateLimiter(options: PostgresRateLimiterOptions = {}): RateLimiter {
  const secret = options.secret ?? getEnv().RATE_LIMIT_KEY_SECRET;
  const hit = options.hit ?? createSupabaseRateLimitHit();

  return {
    async consume(key: RateLimitKey, rule: RateLimitRule): Promise<RateLimitDecision> {
      const raw = await hit({
        bucket: `${key.bucket}:${hmacSubject(secret, key.subject)}`,
        windowSeconds: rule.windowSeconds,
        max: rule.limit,
      });

      const result = hitResultSchema.safeParse(raw);
      if (!result.success) throw new Error('rate_limit_hit returned an unexpected result');

      const [row] = result.data;
      if (row === undefined) throw new Error('rate_limit_hit returned no row');
      if (row.allowed) return { allowed: true };
      return { allowed: false, retryAfterSeconds: Math.max(1, row.retry_after_seconds) };
    },
  };
}
