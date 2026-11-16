import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { createClient } from '../application/create-client';
import { createSupabaseClientRepository } from '../infrastructure/supabase-client-repository';
import { CLIENT_WRITE_RULE } from './client-rate-limits';
import { toClientDetailDto } from './client.dto';
import { createClientBodySchema } from './client.schema';

const CREATED = 201;
const CLIENTS_PATH = '/api/v1/admin/clients';

/**
 * `POST /admin/clients` (operationId `createClient`). Policy equal to the contract: role ceo only,
 * `allowPending: []`, user 60 / min in the `writes` counter. Answers 201 with the new client and a
 * `Location` header that points at it.
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createCreateClientHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [CLIENT_WRITE_RULE],
      body: createClientBodySchema,
    },
    async ({ request, requestId, cookies, logger, principal, body }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });
      const clients = createSupabaseClientRepository(supabase, { logger });

      const result = await createClient({ clients }, principal, { name: body.name });
      if (!result.ok) return result.error;

      return json(CREATED, toClientDetailDto(result.value), {
        headers: { Location: `${CLIENTS_PATH}/${result.value.id}` },
      });
    },
  );
}

export const createClientHandler = createCreateClientHandler();
