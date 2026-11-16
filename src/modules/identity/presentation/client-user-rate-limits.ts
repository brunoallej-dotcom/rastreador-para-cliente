import type { RateLimitRule } from '@/shared/http';

const ONE_MINUTE_SECONDS = 60;
const ONE_HOUR_SECONDS = 60 * 60;

/**
 * `x-rate-limit` of the login list (`listClientUsers`): 300 per minute per CEO, in the shared `reads`
 * counter. Equal to the contract; the handler tests compare them.
 */
export const CLIENT_USER_READ_RULE = {
  scope: 'user',
  group: 'reads',
  limit: 300,
  windowSeconds: ONE_MINUTE_SECONDS,
} as const satisfies RateLimitRule;

/**
 * `x-rate-limit` of the login update (`updateClientUser`): 60 per minute per CEO, in the shared
 * `writes` counter. Equal to the contract; the handler tests compare them.
 */
export const CLIENT_USER_WRITE_RULE = {
  scope: 'user',
  group: 'writes',
  limit: 60,
  windowSeconds: ONE_MINUTE_SECONDS,
} as const satisfies RateLimitRule;

/**
 * `x-rate-limit` of `provisionClientUser` and `resetClientUserPassword`: 20 per hour per CEO, in ONE
 * counter for the two (spec §3.9: both hand out a password). Equal to the contract; the handler tests
 * compare them.
 */
export const CLIENT_USER_ADMIN_RULE = {
  scope: 'user',
  group: 'client-user-admin',
  limit: 20,
  windowSeconds: ONE_HOUR_SECONDS,
} as const satisfies RateLimitRule;
