import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { listClientUsers } from '../application/list-client-users';
import { createSupabaseAccountRepository } from '../infrastructure/supabase-account-repository';
import { toClientUserListDto } from './client-user.dto';
import { CLIENT_USER_READ_RULE } from './client-user-rate-limits';
import { clientIdParamsSchema } from './client-user.schema';

/**
 * `GET /admin/clients/{clientId}/users` (operationId `listClientUsers`). Policy equal to the contract:
 * role ceo only, `allowPending: []`, user 300 / min in the shared `reads` counter. A malformed id is a
 * 400, an unknown client a 404. The tenant is the PATH's only after the pipeline proved the caller is a
 * CEO with an attested `aal2` session.
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createListClientUsersHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [CLIENT_USER_READ_RULE],
      params: clientIdParamsSchema,
    },
    async ({ request, requestId, cookies, logger, principal, params }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });
      const users = createSupabaseAccountRepository(supabase, { logger });

      const result = await listClientUsers({ users }, principal, { clientId: params.clientId });
      return result.ok ? json(200, toClientUserListDto(result.value)) : result.error;
    },
  );
}

export const listClientUsersHandler = createListClientUsersHandler();
