import type { GlobalBudget } from '@/shared/http';

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
