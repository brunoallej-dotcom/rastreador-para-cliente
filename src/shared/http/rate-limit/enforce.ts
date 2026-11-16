import { ServiceUnavailableError } from '@/shared/kernel';
import type { Logger } from '@/shared/observability/logger';
import { RateLimitedError } from '../pipeline-errors';
import { rateLimitBucket } from './group';
import type { RateLimiter, RateLimitRule, RateLimitScope } from './rate-limiter';

export type EnforceRateLimitsInput = {
  readonly limiter: RateLimiter;
  readonly rules: readonly RateLimitRule[];
  /** Only the rules of this scope are enforced. */
  readonly scope: RateLimitScope;
  /** Plaintext subject of the scope: IP (or IPv6 /64), normalized account identifier or user id. */
  readonly subject: string;
  readonly logger: Logger;
};

/** `Retry-After` is a whole number of seconds, at least 1, whatever the limiter returned. */
function retryAfterSeconds(raw: number, rule: RateLimitRule): number {
  const seconds = Math.ceil(raw);
  return Math.max(1, Number.isFinite(seconds) ? seconds : rule.windowSeconds);
}

/**
 * Counts the request against every rule of `scope`, in declaration order.
 * - the first denial → `RateLimitedError` (429), and an `auth.rate_limited` event carrying the
 *   scope and the group (never the subject);
 * - the limiter throwing, or answering something that is not a clear decision →
 *   `ServiceUnavailableError` (503): fail closed, a broken limiter never lets requests through.
 */
export async function enforceRateLimits(input: EnforceRateLimitsInput): Promise<void> {
  const { limiter, rules, scope, subject, logger } = input;

  for (const rule of rules) {
    if (rule.scope !== scope) continue;
    const { group } = rule;

    let decision: Awaited<ReturnType<RateLimiter['consume']>>;
    try {
      decision = await limiter.consume(
        { scope, group, bucket: rateLimitBucket(rule), subject },
        rule,
      );
    } catch (cause) {
      throw new ServiceUnavailableError('rate limiter failed', { cause });
    }

    if (decision.allowed === true) continue;
    if (decision.allowed !== false) {
      throw new ServiceUnavailableError('rate limiter returned an invalid decision');
    }

    logger.warn({ event: 'auth.rate_limited', scope, group }, 'auth.rate_limited');
    throw new RateLimitedError(retryAfterSeconds(decision.retryAfterSeconds, rule));
  }
}
