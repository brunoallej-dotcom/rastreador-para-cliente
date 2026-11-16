import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { getClient } from '../application/get-client';
import { createSupabaseClientRepository } from '../infrastructure/supabase-client-repository';
import { CLIENT_READ_RULE } from './client-rate-limits';
import { toClientDetailDto } from './client.dto';
import { clientIdParamsSchema } from './client.schema';

/**
 * `GET /admin/clients/{clientId}` (operationId `getClient`). Policy equal to the contract: role ceo
 * only, `allowPending: []`, user 300 / min in the `reads` counter. A malformed id is a 400, an
 * unknown one a 404.
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createGetClientHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [CLIENT_READ_RULE],
      params: clientIdParamsSchema,
    },
    async ({ request, requestId, cookies, logger, principal, params }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });
      const clients = createSupabaseClientRepository(supabase, { logger });

      const result = await getClient({ clients }, principal, { clientId: params.clientId });
      return result.ok ? json(200, toClientDetailDto(result.value)) : result.error;
    },
  );
}

export const getClientHandler = createGetClientHandler();
