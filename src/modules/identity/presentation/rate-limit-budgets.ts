import type { GlobalBudget, UserBudget } from '@/shared/http';

/**
 * The aggregate budget of every call to the Auth server that signs a user in with a password,
 * in the `global` scope (F-02): 300 per 300 s, one every second on average. It is spent by
 * `POST /auth/login` and by the sign-in that proves the current password in `POST /auth/password`:
 * both are the same kind of call to Auth, and the Auth server counts sign-ins per source IP, which
 * behind this app is only ever the server's IP. A distributed attacker (20 attempts per /64 is allowed,
 * and there are many /64s) could therefore exhaust that quota and turn login into a 503 for everyone.
 * This budget answers 429 first: it must stay STRICTLY BELOW the project's `sign_in_sign_ups` quota of
 * Auth (`[auth.rate_limit]` in `supabase/config.toml`: 1000 per 5 minutes locally; the hosted project
 * must be configured above this, Wave 11), and far above what a real company's logins need (4 CEOs
 * and a handful of clients per client). A unit test compares the two numbers.
 *
 * It lives here, and not in a handler, so that the handlers that spend it do not depend on each other.
 */
export const LOGIN_GLOBAL_BUDGET = {
  group: 'login',
  limit: 300,
  windowSeconds: 300,
} as const satisfies GlobalBudget;

const SECONDS_PER_DAY = 24 * 60 * 60;

/**
 * The daily cap on code attempts per CEO (F-22), spent by `POST /auth/mfa/totp/verify` with
 * `consumeUserBudget`. The contract's rule (5 per 5 minutes) alone allows 1,440 guesses a day
 * against a six-digit code (three codes are valid at any moment), which finds one in about 8 months
 * on average for an attacker who holds the password. 20 a day (a CEO verifies about once per login)
 * stretches that to decades, and the spend is per user, not per IP, so rotating addresses does not
 * help. It is a programmatic budget on top of the contract's rule, not instead of it: the policy of
 * the route stays equal to `x-rate-limit`.
 */
export const VERIFY_DAILY_BUDGET = {
  group: 'totp-verify-daily',
  limit: 20,
  windowSeconds: SECONDS_PER_DAY,
} as const satisfies UserBudget;

/**
 * Every programmatic budget of the identity module, keyed by the NAME of its constant, with the
 * operations (`operationId` of the contract) that spend it. It is the one place that says "this
 * budget exists and these handlers spend it", and three tests hold it against the rest:
 * the contract (`tests/contract/contract-invariants.test.ts`: each entry is an `x-rate-limit`
 * entry with `programmatic: true`, on exactly those operations, and none is missing), the handlers
 * (`programmatic-budgets.test.ts`: each one really spends it, once) and the source (a scan: no
 * `consumeGlobalBudget`/`consumeUserBudget` call spends anything that is not here).
 *
 * `SESSION_UPSTREAM_RULE` (the per-IP budget of session cookies that make the server call Auth) is
 * not in it: it belongs to `src/shared/http` and is spent by the principal resolver, not a handler.
 */
export const PROGRAMMATIC_BUDGETS = {
  LOGIN_GLOBAL_BUDGET: {
    scope: 'global',
    budget: LOGIN_GLOBAL_BUDGET,
    spentBy: ['login', 'changePassword'],
  },
  VERIFY_DAILY_BUDGET: {
    scope: 'user',
    budget: VERIFY_DAILY_BUDGET,
    spentBy: ['verifyTotp'],
  },
} as const satisfies Record<
  string,
  {
    readonly scope: 'global' | 'user';
    readonly budget: GlobalBudget | UserBudget;
    readonly spentBy: readonly string[];
  }
>;
