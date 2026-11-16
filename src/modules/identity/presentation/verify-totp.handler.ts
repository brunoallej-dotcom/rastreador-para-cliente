import { getRequestSupabase } from '@/shared/db/server-client';
import {
  readAccessToken,
  sessionIdOfToken,
  snapshotSessionCookies,
} from '@/shared/db/session-cookies';
import { clientIpFingerprint, json, withRoute, type WithRoute } from '@/shared/http';
import { verifyTotp } from '../application/verify-totp';
import { InvalidMfaCodeError } from '../domain/mfa-errors';
import { createSupabaseMfaGateway } from '../infrastructure/supabase-mfa-gateway';
import { createTrackingClientDirectory } from '../infrastructure/tracking-client-directory';
import { VERIFY_DAILY_BUDGET } from './rate-limit-budgets';
import { toSessionDto } from './session.dto';
import { verifyTotpBodySchema } from './verify-totp.schema';

/** Where the factor of a verification came from, for the log: lets us see who still sends the id. */
const factorSourceOf = (body: { factorId?: string | undefined }) =>
  body.factorId === undefined ? 'session' : 'request';

const VERIFY_LIMIT = 5;
const FIVE_MINUTES_SECONDS = 5 * 60;

/**
 * `POST /auth/mfa/totp/verify` (operationId `verifyTotp`). Policy equal to the contract: role ceo
 * only, `allowPending: [ENROLL_MFA, VERIFY_MFA]` (the first verification activates the factor; a
 * later login verifies it to reach `aal2`; a pending password change still blocks it), user 5 /
 * 5 min in the `totp-verify` counter.
 *
 * The limit is on the route, so EVERY request spends one unit, a correct code too (E-28: a wrong
 * code is counted, and the sixth request in five minutes is 429 whatever it carries). The
 * pipeline spends it before the code is looked at.
 *
 * On success the session becomes `aal2`: `mfa.verify` issues new tokens, the request's Supabase
 * client (the one the principal resolver used) writes them to the pipeline's jar, and the pipeline
 * puts the cookies on the response. A refused code writes nothing. The old `aal1` access token
 * keeps working as what it is: an `aal1` session, which every CEO route refuses (pending
 * `VERIFY_MFA`; and the database functions of the CEO ask `aal2` of the JWT itself).
 *
 * On top of the contract's rule, every attempt that gets past it also spends the daily cap
 * (`VERIFY_DAILY_BUDGET`, 429 over it). A wrong code, a replayed one (the database refuses a code it
 * already accepted in the last 120 s) and a factor that is not the CEO's all answer the same 422.
 *
 * The body's `factorId` is optional and deprecated: left out, the use case resolves the CEO's TOTP
 * factor from the session itself, with the same request client (no admin client). Both budgets are
 * spent before that, so leaving the field out buys no extra attempt.
 *
 * When the verification activated the FIRST factor, the use case signs the CEO out of their other
 * sessions. It is best effort: a failure is logged at warn level and the verification stands.
 *
 * The log carries ids and a reason, never the code, the secret or a token.
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createVerifyTotpHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: ['ENROLL_MFA', 'VERIFY_MFA'],
      rateLimit: [
        {
          scope: 'user',
          group: 'totp-verify',
          limit: VERIFY_LIMIT,
          windowSeconds: FIVE_MINUTES_SECONDS,
        },
      ],
      body: verifyTotpBodySchema,
    },
    async ({ request, requestId, cookies, logger, principal, body, consumeUserBudget }) => {
      // After the contract's rule (spent by the pipeline), before the code is looked at.
      await consumeUserBudget(VERIFY_DAILY_BUDGET);

      const supabase = getRequestSupabase({ request, cookies, requestId });
      const gateway = createSupabaseMfaGateway(supabase);

      const result = await verifyTotp(
        { mfa: gateway, principals: gateway, clients: createTrackingClientDirectory(supabase) },
        principal,
        body,
      );

      if (!result.ok) {
        if (result.error instanceof InvalidMfaCodeError) {
          logger.warn(
            {
              event: 'auth.mfa.failed',
              userId: principal.userId,
              factorId: result.error.factorId,
              factorSource: factorSourceOf(body),
              reason: result.error.reason,
              ipHash: clientIpFingerprint(request),
            },
            'auth.mfa.failed',
          );
        }
        return result.error;
      }

      const { session, activated, otherSessionsRevoked } = result.value;

      // The id of the session the verification elevated: the same one as before, with new tokens.
      const accessToken = readAccessToken(snapshotSessionCookies(cookies));
      logger.info(
        {
          event: 'auth.mfa.verified',
          userId: principal.userId,
          factorId: result.value.factorId,
          factorSource: factorSourceOf(body),
          sessionId: accessToken === undefined ? undefined : sessionIdOfToken(accessToken),
          activated,
          ipHash: clientIpFingerprint(request),
        },
        'auth.mfa.verified',
      );
      // Best effort: a failed revocation is a warning, and the verification stands.
      if (otherSessionsRevoked === false) {
        logger.warn(
          {
            event: 'auth.mfa.followup_failed',
            userId: principal.userId,
            step: 'revoke_other_sessions',
          },
          'auth.mfa.followup_failed',
        );
      }
      return json(200, toSessionDto(session));
    },
  );
}

export const verifyTotpHandler = createVerifyTotpHandler();
