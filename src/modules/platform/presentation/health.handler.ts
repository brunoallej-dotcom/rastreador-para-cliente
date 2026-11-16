import { json, withRoute } from '@/shared/http';

const HEALTH_RATE_LIMIT_PER_MINUTE = 60;
const ONE_MINUTE_SECONDS = 60;

/**
 * `GET /health` (operationId `getHealth`): public liveness check. Same policy as the contract:
 * `x-auth-policy: public`, `x-rate-limit: ip 60/60s`. It exposes no version, dependency or other
 * internal detail, and its handler touches no dependency.
 *
 * The pipeline around it does use the rate limiter, though, and the contract documents only 200
 * and 429 for this route. `pipeline-deps.ts` therefore keeps the `health` group OFF the Postgres
 * limiter (it routes that group to an in-memory limiter), so a database outage can never turn a
 * liveness probe into an undocumented 503.
 */
export const healthHandler = withRoute(
  {
    access: 'public',
    rateLimit: [
      {
        scope: 'ip',
        group: 'health',
        limit: HEALTH_RATE_LIMIT_PER_MINUTE,
        windowSeconds: ONE_MINUTE_SECONDS,
      },
    ],
  },
  () => json(200, { status: 'ok' }),
);
