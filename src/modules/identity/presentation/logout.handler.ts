import { getRequestSupabase } from '@/shared/db/server-client';
import {
  readAccessToken,
  restoreSessionCookies,
  snapshotSessionCookies,
} from '@/shared/db/session-cookies';
import { noContent, withRoute } from '@/shared/http';
import { logout } from '../application/logout';
import { createSupabaseAuthGateway } from '../infrastructure/supabase-auth-gateway';

const WRITES_LIMIT = 60;
const ONE_MINUTE_SECONDS = 60;

/**
 * `POST /auth/logout` (operationId `logout`). Policy equal to the contract: roles client and ceo,
 * every pending action allowed (a user who must still change the password can leave), user
 * 60 / min in the shared `writes` counter. It has no body schema, so the body is ignored.
 *
 * It ends THIS session only (E-09) and revokes it on the server, so the old cookie is useless
 * afterwards (AC-04). The client library drops the session cookies from the response before it
 * has confirmed the revocation, and it reports success even when the Auth server answered 401,
 * 403 or 404 to the revocation without revoking anything. So the gateway asks the database whether
 * the old token still yields a principal; if the revocation failed or cannot be confirmed, the
 * cookies are put back and the answer is 503: the browser keeps a session it can use to try again
 * instead of silently holding a live session it can no longer reach.
 */
export const logoutHandler = withRoute(
  {
    access: 'authenticated',
    roles: ['client', 'ceo'],
    allowPending: ['CHANGE_PASSWORD', 'ENROLL_MFA', 'VERIFY_MFA'],
    rateLimit: [
      { scope: 'user', group: 'writes', limit: WRITES_LIMIT, windowSeconds: ONE_MINUTE_SECONDS },
    ],
  },
  async ({ request, requestId, cookies, logger, principal }) => {
    const supabase = getRequestSupabase({ request, cookies, requestId });
    const sessionCookies = snapshotSessionCookies(cookies);
    // An authenticated request always carries a session token; failing closed beats a logout whose
    // revocation nobody can confirm.
    const accessToken = readAccessToken(sessionCookies);
    if (accessToken === undefined) throw new Error('an authenticated request has no access token');

    try {
      const result = await logout({
        auth: createSupabaseAuthGateway(supabase, { confirmRevocationOf: accessToken }),
      });
      if (!result.ok) {
        restoreSessionCookies(cookies, sessionCookies);
        return result.error;
      }
    } catch (error) {
      restoreSessionCookies(cookies, sessionCookies);
      throw error;
    }

    logger.info({ event: 'auth.logout', userId: principal.userId }, 'auth.logout');
    return noContent();
  },
);
