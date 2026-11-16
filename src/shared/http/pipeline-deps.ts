import { getEnv } from '@/shared/config/env';
import { getLogger, type Logger } from '@/shared/observability/logger';
import { resolveAllowedOrigins } from './origin';
import { createGroupRoutedRateLimiter } from './rate-limit/group-routed-rate-limiter';
import { createInMemoryRateLimiter } from './rate-limit/in-memory-rate-limiter';
import { createPostgresRateLimiter } from './rate-limit/postgres-rate-limiter';
import type { RateLimiter } from './rate-limit/rate-limiter';
import type { PrincipalResolver } from './principal-resolver';
import { createSupabasePrincipalResolver } from './supabase-principal-resolver';

/** The platform dependencies of the pipeline. Unit tests pass fakes through `createWithRoute`. */
export type PipelineDeps = {
  readonly rateLimiter: RateLimiter;
  readonly principalResolver: PrincipalResolver;
  /** Origins accepted on unsafe methods (SEC-08). */
  readonly allowedOrigins: readonly string[];
  /**
   * When true, a request the platform gave no client IP for is refused with 503 instead of
   * falling into the shared `unknown` rate-limit bucket. True in production, false in dev/tests.
   */
  readonly requireClientIp: boolean;
  /** Root logger; the pipeline derives a per-request child with the `requestId`. */
  readonly logger: Logger;
};

/**
 * PRODUCTION WIRING: the single place that decides which rate limiter and which principal
 * resolver the real `withRoute` uses.
 *
 * - Rate limiter: the Postgres counters (ADR 0004), shared by every serverless instance, with the
 *   `health` group kept OFF the database: `GET /health` documents no 503, so a database outage
 *   must not be able to turn a liveness probe into an undocumented 503. `health` stays on an
 *   in-memory limiter (per instance, which is enough for a liveness probe).
 * - Principal resolver: `getClaims()` + `current_principal()` (spec §3.4).
 */
function buildPipelineDeps(): PipelineDeps {
  const env = getEnv();
  return {
    rateLimiter: createGroupRoutedRateLimiter({
      routes: { health: createInMemoryRateLimiter() },
      fallback: createPostgresRateLimiter(),
    }),
    principalResolver: createSupabasePrincipalResolver(),
    allowedOrigins: resolveAllowedOrigins(env),
    requireClientIp: env.VERCEL_ENV === 'production',
    logger: getLogger(),
  };
}

let cached: PipelineDeps | undefined;

/**
 * Built on first use and kept for the life of the process (the limiter must keep its counters).
 * Lazy because `next build` runs without env; `register()` in `instrumentation.ts` already
 * crashes the boot on invalid env, so this never throws on a running server.
 */
export function getPipelineDeps(): PipelineDeps {
  cached ??= buildPipelineDeps();
  return cached;
}
