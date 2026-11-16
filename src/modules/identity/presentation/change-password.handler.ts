import { getRequestSupabase } from '@/shared/db/server-client';
import {
  readAccessToken,
  sessionIdOfToken,
  snapshotSessionCookies,
} from '@/shared/db/session-cookies';
import { clientIpFingerprint, noContent, withRoute, type WithRoute } from '@/shared/http';
import { DomainError, ServiceUnavailableError } from '@/shared/kernel';
import { changePassword } from '../application/change-password';
import { UnexpectedAuthAnswerError } from '../domain/errors';
import { PasswordChangeIncompleteError } from '../domain/password-errors';
import { createReauthClient } from '../infrastructure/reauth-client';
import { createSupabasePasswordGateway } from '../infrastructure/supabase-password-gateway';
import { changePasswordBodySchema } from './change-password.schema';
import { LOGIN_GLOBAL_BUDGET } from './login.handler';

const PASSWORD_CHANGE_LIMIT = 5;
const FIFTEEN_MINUTES_SECONDS = 15 * 60;

/**
 * The categories of `auth.password_change.failed`: the code of the refusal (`WEAK_PASSWORD`,
 * `PASSWORD_UNCHANGED`, `INVALID_CURRENT_PASSWORD`, `FORBIDDEN`), or one of the two failures of the
 * service. Fixed text, never a password and never what Auth said.
 */
type PasswordChangeFailureReason = DomainError['code'] | 'upstream_unavailable' | 'upstream_error';

/**
 * `POST /auth/password` (operationId `changePassword`). Policy equal to the contract: roles client
 * and ceo, `allowPending` CHANGE_PASSWORD and ENROLL_MFA (a CEO who has not enrolled the second
 * factor can still change the first-access password; one with a verified factor and an `aal1`
 * session gets 403 `MFA_VERIFICATION_REQUIRED` from the pipeline), user 5 / 15 min in the
 * `password-change` counter. Every request spends that budget, a refused one too, so the route
 * cannot be used to guess the current password faster than 5 times per 15 minutes.
 *
 * It proves the current password by signing in on a throwaway client (ADR 0010), which spends the
 * global login budget like any sign-in does (F-02), and nothing from that session reaches the
 * response. The new password is set with the user's own session, whose cookies stay in the pipeline's
 * jar (not a buffer): if the Auth client rotates the session while it works, the rotated cookies
 * MUST reach the browser even when a later step fails, or the old refresh token would be reused.
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createChangePasswordHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['client', 'ceo'],
      allowPending: ['CHANGE_PASSWORD', 'ENROLL_MFA'],
      rateLimit: [
        {
          scope: 'user',
          group: 'password-change',
          limit: PASSWORD_CHANGE_LIMIT,
          windowSeconds: FIFTEEN_MINUTES_SECONDS,
        },
      ],
      body: changePasswordBodySchema,
    },
    async ({ request, requestId, cookies, logger, principal, body, consumeGlobalBudget }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });
      const sessionId = sessionIdOfToken(readAccessToken(snapshotSessionCookies(cookies)) ?? '');
      const gateway = createSupabasePasswordGateway(supabase, {
        reauth: createReauthClient({ requestId }),
        logger,
        // Before the sign-in that proves the password, and never when a pure check already refused:
        // the sign-in is a call to Auth like a login, so it is charged to the same budget.
        beforeReauthentication: () => consumeGlobalBudget(LOGIN_GLOBAL_BUDGET),
      });

      const logFailure = (reason: PasswordChangeFailureReason, details: object = {}) =>
        logger.warn(
          {
            event: 'auth.password_change.failed',
            userId: principal.userId,
            sessionId,
            ipHash: clientIpFingerprint(request),
            reason,
            ...details,
          },
          'auth.password_change.failed',
        );

      let result: Awaited<ReturnType<typeof changePassword>>;
      try {
        result = await changePassword({ passwords: gateway }, body);
      } catch (error) {
        if (error instanceof PasswordChangeIncompleteError) {
          // The password IS new but the account still says "change it": a person must be able to
          // find this line (the response tells the client how to finish).
          logger.error(
            { event: 'auth.password_change.incomplete', userId: principal.userId, sessionId },
            'auth.password_change.incomplete',
          );
        } else if (error instanceof UnexpectedAuthAnswerError) {
          logFailure('upstream_error', { authStatus: error.authStatus, authCode: error.authCode });
        } else if (error instanceof ServiceUnavailableError) {
          logFailure('upstream_unavailable');
        } else if (!(error instanceof DomainError)) {
          // a rate limit or another pipeline denial is logged by the pipeline itself
          logFailure('upstream_error');
        }
        throw error;
      }

      if (!result.ok) {
        logFailure(result.error.code);
        return result.error;
      }

      logger.info(
        {
          event: 'auth.password_changed',
          userId: principal.userId,
          sessionId,
          ipHash: clientIpFingerprint(request),
        },
        'auth.password_changed',
      );
      return noContent();
    },
  );
}

export const changePasswordHandler = createChangePasswordHandler();
