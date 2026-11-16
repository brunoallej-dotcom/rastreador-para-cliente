import { z } from 'zod';
import { PENDING_ACTIONS, ROLES } from '@/shared/kernel';
import {
  RATE_LIMIT_GROUPS,
  type RateLimitRule,
  type RateLimitScope,
} from './rate-limit/rate-limiter';
import type { RuntimePolicy } from './route-policy';
import type { InputSchema } from './validation';

/** The scopes a route policy may declare; `global` is a programmatic budget, never a policy. */
const RATE_LIMIT_SCOPES: readonly RateLimitScope[] = ['ip', 'account', 'user'];

const isPositiveInteger = (value: number) => Number.isInteger(value) && value > 0;

/** A strict Zod object has `z.never()` as its catchall: unknown keys are rejected. */
function isStrictObject(schema: InputSchema): boolean {
  return schema instanceof z.ZodObject && schema._zod.def.catchall?._zod.def.type === 'never';
}

function assertRule(rule: RateLimitRule, policy: RuntimePolicy): void {
  if (rule.scope === 'global') {
    throw new Error(
      'withRoute: the "global" rate-limit scope is not allowed in a route policy; ' +
        'a handler spends a global budget with `consumeGlobalBudget` (or a per-user one with `consumeUserBudget`)',
    );
  }
  if (!RATE_LIMIT_SCOPES.includes(rule.scope)) {
    throw new Error(`withRoute: unknown rate-limit scope "${String(rule.scope)}"`);
  }
  if (!RATE_LIMIT_GROUPS.includes(rule.group)) {
    throw new Error(`withRoute: unknown rate-limit group "${String(rule.group)}"`);
  }
  if (!isPositiveInteger(rule.limit) || !isPositiveInteger(rule.windowSeconds)) {
    throw new Error('withRoute: rate-limit "limit" and "windowSeconds" must be positive integers');
  }
  if (rule.scope === 'user' && policy.access !== 'authenticated') {
    throw new Error('withRoute: "user" rate-limit rules need an authenticated route');
  }
  if (rule.scope === 'account' && policy.access !== 'public') {
    throw new Error('withRoute: "account" rate-limit rules are only for public routes');
  }
  if (rule.scope === 'account' && (policy.accountKey === undefined || policy.body === undefined)) {
    throw new Error(
      'withRoute: "account" rate-limit rules need both "accountKey" and a "body" schema',
    );
  }
}

/**
 * Programmer-error checks, run once when a route is defined (so at module load, and `next build`
 * fails) instead of on the first request: a malformed policy must never reach production.
 */
export function assertValidPolicy(policy: RuntimePolicy): void {
  if (policy.access === 'authenticated') {
    const { roles, allowPending } = policy;
    if (roles === undefined || roles.length === 0 || !roles.every((role) => ROLES.includes(role))) {
      throw new Error('withRoute: an authenticated route needs a non-empty list of valid roles');
    }
    if (allowPending === undefined || !allowPending.every((a) => PENDING_ACTIONS.includes(a))) {
      throw new Error('withRoute: an authenticated route needs "allowPending" (use [] for none)');
    }
  } else if (policy.access === 'public') {
    if (policy.roles !== undefined || policy.allowPending !== undefined) {
      throw new Error('withRoute: a public route has no roles or allowPending');
    }
  } else {
    throw new Error('withRoute: policy.access must be "public" or "authenticated"');
  }

  // Every route is rate limited: the contract declares x-rate-limit on every operation.
  const rules = policy.rateLimit;
  if (rules === undefined || rules.length === 0) {
    throw new Error('withRoute: every route needs a non-empty "rateLimit" (x-rate-limit)');
  }
  for (const rule of rules) assertRule(rule, policy);
  if (policy.access === 'public' && !rules.some((rule) => rule.scope === 'ip')) {
    throw new Error('withRoute: a public route needs at least one "ip" rate-limit rule');
  }

  for (const part of ['params', 'query', 'body'] as const) {
    const schema = policy[part];
    if (schema !== undefined && !isStrictObject(schema)) {
      throw new Error(`withRoute: the "${part}" schema must be a strict Zod object (.strict())`);
    }
  }
}
