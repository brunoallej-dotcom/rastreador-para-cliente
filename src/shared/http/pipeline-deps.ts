import { getEnv } from '@/shared/config/env';
import { getLogger, type Logger } from '@/shared/observability/logger';
import { noPrincipalResolver } from './fake-principal-resolver';
import { resolveAllowedOrigins } from './origin';
import { createInMemoryRateLimiter } from './rate-limit/in-memory-rate-limiter';
import type { RateLimiter } from './rate-limit/rate-limiter';
import type { PrincipalResolver } from './principal-resolver';

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
 * resolver the real `withRoute` uses. Wave 3 replaces the two lines marked below (Postgres
 * limiter, Supabase resolver) and edits nothing else in `src/shared/http`.
 *
 * Wave 3 must keep the `health` group OFF the Postgres limiter (route it to an in-memory limiter,
 * for example a limiter that picks by `key.group`): `GET /health` documents no 503, so a database
 * outage must not be able to turn a liveness probe into an undocumented 503.
 */
function buildPipelineDeps(): PipelineDeps {
  const env = getEnv();
  return {
    // Wave 3: replace with the Postgres-backed limiter (ADR 0004).
    rateLimiter: createInMemoryRateLimiter(),
    // Wave 3: replace with the Supabase resolver (getClaims + current_principal()).
    // Until then nobody authenticates: authenticated routes answer 401.
    principalResolver: noPrincipalResolver,
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
