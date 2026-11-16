import type { RateLimitRule } from '@/shared/http';

const ONE_MINUTE_SECONDS = 60;

/**
 * `x-rate-limit` of the process reads (`listClientProcesses`, `getProcess`,
 * `getDefaultStageTemplate`): 300 per minute per CEO, in the shared `reads` counter. Equal to the
 * contract; the handler tests compare them.
 */
export const PROCESS_READ_RULE = {
  scope: 'user',
  group: 'reads',
  limit: 300,
  windowSeconds: ONE_MINUTE_SECONDS,
} as const satisfies RateLimitRule;

/**
 * `x-rate-limit` of the process writes (`createProcess`, `updateProcess`): 60 per minute per CEO, in
 * the shared `writes` counter. Equal to the contract; the handler tests compare them.
 */
export const PROCESS_WRITE_RULE = {
  scope: 'user',
  group: 'writes',
  limit: 60,
  windowSeconds: ONE_MINUTE_SECONDS,
} as const satisfies RateLimitRule;
