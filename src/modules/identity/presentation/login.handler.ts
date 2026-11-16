import { getRequestSupabase } from '@/shared/db/server-client';
import {
  bufferCookies,
  clientIpFingerprint,
  fingerprintSubject,
  json,
  startResponseFloor,
  withRoute,
  type GlobalBudget,
  type WithRoute,
} from '@/shared/http';
import { ServiceUnavailableError } from '@/shared/kernel';
import { login } from '../application/login';
import { UnexpectedAuthAnswerError, type CredentialsRefusal } from '../domain/errors';
import { createSupabaseAuthGateway } from '../infrastructure/supabase-auth-gateway';
import { createTrackingClientDirectory } from '../infrastructure/tracking-client-directory';
import { loginBodySchema } from './login.schema';
import { toSessionDto } from './session.dto';

/**
 * The categories of `auth.login.failed`: the two refusals of credentials (see
 * `CredentialsRefusal`) and the two failures of the service. `upstream_error` is anything else that
 * went wrong while talking to Supabase (an Auth answer nobody expected, a row nobody understands).
 */
type LoginFailureReason = CredentialsRefusal | 'upstream_unavailable' | 'upstream_error';

const LOGIN_IP_LIMIT = 20;
const LOGIN_ACCOUNT_LIMIT = 10;
const FIFTEEN_MINUTES_SECONDS = 15 * 60;

/**
 * The aggregate budget of ALL logins together, in the `global` scope (F-02): 300 per 300 s, one
 * every second on average. The Auth server counts sign-ins per source IP and, behind this app, it
 * only ever sees the server's IP. A distributed attacker (20 attempts per /64 is allowed, and
 * there are many /64s) could therefore exhaust that quota and turn login into a 503 for everyone.
 * This budget answers 429 first: it must stay STRICTLY BELOW the project's `sign_in_sign_ups`
 * quota of Auth (`[auth.rate_limit]` in `supabase/config.toml`: 1000 per 5 minutes locally; the
 * hosted project must be configured above this, Wave 11), and far above what a real company's
 * logins need (4 CEOs and a handful of clients per client). A unit test compares the two numbers.
 */
export const LOGIN_GLOBAL_BUDGET = {
  group: 'login',
  limit: 300,
  windowSeconds: 300,
} as const satisfies GlobalBudget;

/**
 * A refused login (401) answers no sooner than 400 ms after the handler started, plus up to 100 ms
 * of random jitter (F-05). The refusals take different times: an unknown e-mail and a wrong
 * password cost one call to Auth, and a disabled account costs three (sign in, read the principal,
 * revoke the session), which a caller who knows the password could use to tell a disabled account
 * from a wrong password. The floor is above the slowest refused path, so they all answer alike; if
 * Auth is slower than the floor, nothing is added.
 */
export const REFUSED_LOGIN_FLOOR_MS = 400;
export const REFUSED_LOGIN_JITTER_MS = 100;

/**
 * `POST /auth/login` (operationId `login`). Policy equal to the contract: `x-auth-policy: public`
 * and `x-rate-limit` ip 20 / 15 min plus account 10 / 15 min (the account key is the normalized
 * e-mail, so `A@x.com` and `a@x.com` share one budget). On top of that, every login spends the
 * global budget (`LOGIN_GLOBAL_BUDGET`) before anything calls Auth: over it, 429 `RATE_LIMITED`.
 *
 * The session cookies the sign-in writes wait in a buffer and are applied to the response only if
 * the login succeeds. A refused login, including a disabled account whose credentials were right,
 * therefore answers with exactly the same status, body and headers (`Set-Cookie` too) as a wrong
 * password (SEC-12, AC-02), and after the same minimum time (F-05).
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createLoginHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'public',
      rateLimit: [
        {
          scope: 'ip',
          group: 'login',
          limit: LOGIN_IP_LIMIT,
          windowSeconds: FIFTEEN_MINUTES_SECONDS,
        },
        {
          scope: 'account',
          group: 'login',
          limit: LOGIN_ACCOUNT_LIMIT,
          windowSeconds: FIFTEEN_MINUTES_SECONDS,
        },
      ],
      body: loginBodySchema,
      accountKey: (body) => body.email,
    },
    async ({ request, requestId, cookies, logger, body, consumeGlobalBudget }) => {
      const floor = startResponseFloor(REFUSED_LOGIN_FLOOR_MS, REFUSED_LOGIN_JITTER_MS);

      // Before Auth is called, before a client is even built: over budget, nothing reaches Auth.
      await consumeGlobalBudget(LOGIN_GLOBAL_BUDGET);

      const sessionCookies = bufferCookies(cookies);
      const supabase = getRequestSupabase({ request, cookies: sessionCookies, requestId });
      const gateway = createSupabaseAuthGateway(supabase);

      // E-mail, password and IP never reach a log line: only keyed fingerprints of the e-mail and
      // of the IP, and a reason from a fixed list of categories (the response never says which one
      // it was). For an unexpected Auth answer the status and the error code of Auth go along:
      // they carry no personal data and are what tells a misconfigured key from a wrong password.
      const logFailure = (reason: LoginFailureReason, details: Record<string, unknown> = {}) =>
        logger.warn(
          {
            event: 'auth.login.failed',
            accountHash: fingerprintSubject(body.email),
            ipHash: clientIpFingerprint(request),
            reason,
            ...details,
          },
          'auth.login.failed',
        );

      let result: Awaited<ReturnType<typeof login>>;
      try {
        result = await login(
          { auth: gateway, principals: gateway, clients: createTrackingClientDirectory(supabase) },
          body,
        );
      } catch (error) {
        sessionCookies.discard();
        if (error instanceof UnexpectedAuthAnswerError) {
          logFailure('upstream_error', { authStatus: error.authStatus, authCode: error.authCode });
        } else if (error instanceof ServiceUnavailableError) {
          logFailure('upstream_unavailable');
        } else {
          logFailure('upstream_error');
        }
        throw error;
      }

      if (!result.ok) {
        sessionCookies.discard();
        logFailure(result.error.reason);
        // The floor goes AFTER the work and the log, and only on a refusal of credentials.
        await floor.wait();
        return result.error;
      }

      // Everything that can throw comes BEFORE the commit: a 500 must never carry the cookie of a
      // live session.
      const { session, sessionId } = result.value;
      const response = json(200, toSessionDto(session));
      logger.info(
        {
          event: 'auth.login.succeeded',
          userId: session.principal.userId,
          sessionId,
          ipHash: clientIpFingerprint(request),
        },
        'auth.login.succeeded',
      );
      sessionCookies.commit();
      return response;
    },
  );
}

export const loginHandler = createLoginHandler();
