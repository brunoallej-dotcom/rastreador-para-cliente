import type { RateLimitRule } from './rate-limiter';

/**
 * Counter family of a rule: `<scope>:<group>`, e.g. `user:writes`, `ip:login`, `account:login`.
 * The named `group` (spec §3.9) is declared on the rule, not derived from its numbers.
 */
export function rateLimitBucket(rule: Pick<RateLimitRule, 'scope' | 'group'>): string {
  return `${rule.scope}:${rule.group}`;
}
