import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute } from '@/shared/http';
import { getSession } from '../application/get-session';
import { createTrackingClientDirectory } from '../infrastructure/tracking-client-directory';
import { toSessionDto } from './session.dto';

const READS_LIMIT = 300;
const ONE_MINUTE_SECONDS = 60;

/**
 * `GET /auth/session` (operationId `getSession`). Policy equal to the contract: roles client and
 * ceo, every pending action allowed (it is how a client learns what is pending), user 300 / min in
 * the shared `reads` counter. The tenant comes from the session, never from the request.
 */
export const getSessionHandler = withRoute(
  {
    access: 'authenticated',
    roles: ['client', 'ceo'],
    allowPending: ['CHANGE_PASSWORD', 'ENROLL_MFA', 'VERIFY_MFA'],
    rateLimit: [
      { scope: 'user', group: 'reads', limit: READS_LIMIT, windowSeconds: ONE_MINUTE_SECONDS },
    ],
  },
  async ({ request, requestId, cookies, principal }) => {
    const supabase = getRequestSupabase({ request, cookies, requestId });
    const result = await getSession(
      { clients: createTrackingClientDirectory(supabase) },
      principal,
    );
    return result.ok ? json(200, toSessionDto(result.value)) : result.error;
  },
);
