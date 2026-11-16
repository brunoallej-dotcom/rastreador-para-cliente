import { getRequestSupabase } from '@/shared/db/server-client';
import { bufferCookies, fingerprintSubject, json, withRoute } from '@/shared/http';
import { ServiceUnavailableError } from '@/shared/kernel';
import { login } from '../application/login';
import { createSupabaseAuthGateway } from '../infrastructure/supabase-auth-gateway';
import { createTrackingClientDirectory } from '../infrastructure/tracking-client-directory';
import { loginBodySchema } from './login.schema';
import { toSessionDto } from './session.dto';

const LOGIN_IP_LIMIT = 20;
const LOGIN_ACCOUNT_LIMIT = 10;
const FIFTEEN_MINUTES_SECONDS = 15 * 60;

/**
 * `POST /auth/login` (operationId `login`). Policy equal to the contract: `x-auth-policy: public`
 * and `x-rate-limit` ip 20 / 15 min plus account 10 / 15 min (the account key is the normalized
 * e-mail, so `A@x.com` and `a@x.com` share one budget).
 *
 * The session cookies the sign-in writes wait in a buffer and are applied to the response only if
 * the login succeeds. A refused login, including a disabled account whose credentials were right,
 * therefore answers with exactly the same status, body and headers (`Set-Cookie` too) as a wrong
 * password (SEC-12, AC-02).
 */
export const loginHandler = withRoute(
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
  async ({ request, requestId, cookies, logger, body }) => {
    const sessionCookies = bufferCookies(cookies);
    const supabase = getRequestSupabase({ request, cookies: sessionCookies, requestId });
    const gateway = createSupabaseAuthGateway(supabase);

    // E-mail and password never reach a log line: only an HMAC of the e-mail and a generic reason.
    const logFailure = (reason: string) =>
      logger.warn(
        { event: 'auth.login.failed', accountHash: fingerprintSubject(body.email), reason },
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
      logFailure(
        error instanceof ServiceUnavailableError ? 'service_unavailable' : 'internal_error',
      );
      throw error;
    }

    if (!result.ok) {
      sessionCookies.discard();
      logFailure('invalid_credentials');
      return result.error;
    }

    // Everything that can throw comes BEFORE the commit: a 500 must never carry the cookie of a
    // live session.
    const response = json(200, toSessionDto(result.value));
    logger.info(
      { event: 'auth.login.succeeded', userId: result.value.principal.userId },
      'auth.login.succeeded',
    );
    sessionCookies.commit();
    return response;
  },
);
