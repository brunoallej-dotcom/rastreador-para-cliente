import type { RateLimitRule } from '@/shared/http';

const ONE_MINUTE_SECONDS = 60;

/**
 * `x-rate-limit` of the client panel reads (`listMyProcesses`, `getMyProcess`): 300 per minute per
 * user, in the shared `reads` counter (the counter is per user, so a client never spends a CEO's).
 * Equal to the contract; the handler tests compare them.
 */
export const MY_PROCESS_READ_RULE = {
  scope: 'user',
  group: 'reads',
  limit: 300,
  windowSeconds: ONE_MINUTE_SECONDS,
} as const satisfies RateLimitRule;
