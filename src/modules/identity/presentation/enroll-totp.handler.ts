import { getRequestSupabase } from '@/shared/db/server-client';
import { clientIpFingerprint, json, withRoute, type WithRoute } from '@/shared/http';
import { enrollTotp } from '../application/enroll-totp';
import { createSupabaseMfaGateway } from '../infrastructure/supabase-mfa-gateway';
import { toTotpEnrollmentDto } from './totp.dto';

const ENROLL_LIMIT = 10;
const FIFTEEN_MINUTES_SECONDS = 15 * 60;

/**
 * `POST /auth/mfa/totp/enroll` (operationId `enrollTotp`). Policy equal to the contract: role ceo
 * only, `allowPending: [ENROLL_MFA]` (so a CEO who still has to change the password gets 403
 * `PASSWORD_CHANGE_REQUIRED` first, and one who already has a verified factor but an `aal1`
 * session gets 403 `MFA_VERIFICATION_REQUIRED`), user 10 / 15 min in the `totp-enroll` counter. It
 * has no body schema, so the body is ignored.
 *
 * It does not change the session: no cookie is written beyond a refresh the pipeline already did.
 * The response carries the TOTP secret, once; the log line `auth.mfa.enrolled` carries only ids.
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createEnrollTotpHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: ['ENROLL_MFA'],
      rateLimit: [
        {
          scope: 'user',
          group: 'totp-enroll',
          limit: ENROLL_LIMIT,
          windowSeconds: FIFTEEN_MINUTES_SECONDS,
        },
      ],
    },
    async ({ request, requestId, cookies, logger, principal }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });
      const result = await enrollTotp({ mfa: createSupabaseMfaGateway(supabase) }, principal);
      if (!result.ok) return result.error;

      const { enrollment, replacedFactors } = result.value;
      // Ids and a count only. Never the secret, the URI or the QR code (they are in the response).
      logger.info(
        {
          event: 'auth.mfa.enrolled',
          userId: principal.userId,
          factorId: enrollment.factorId,
          replacedFactors,
          ipHash: clientIpFingerprint(request),
        },
        'auth.mfa.enrolled',
      );
      return json(200, toTotpEnrollmentDto(enrollment));
    },
  );
}

export const enrollTotpHandler = createEnrollTotpHandler();
