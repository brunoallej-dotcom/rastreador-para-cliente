import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { updateClient } from '../application/update-client';
import type { ClientPatch } from '../domain/client';
import { createSupabaseClientRepository } from '../infrastructure/supabase-client-repository';
import { CLIENT_WRITE_RULE } from './client-rate-limits';
import { toClientDetailDto } from './client.dto';
import { clientIdParamsSchema, updateClientBodySchema } from './client.schema';

/**
 * `PATCH /admin/clients/{clientId}` (operationId `updateClient`). Policy equal to the contract: role
 * ceo only, `allowPending: []`, user 60 / min in the `writes` counter. Renames, archives or
 * unarchives; the body must name at least one of `name` and `archived`.
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createUpdateClientHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [CLIENT_WRITE_RULE],
      params: clientIdParamsSchema,
      body: updateClientBodySchema,
    },
    async ({ request, requestId, cookies, logger, principal, params, body }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });
      const clients = createSupabaseClientRepository(supabase, { logger });

      // Only the fields the body carries: a missing one is left alone.
      const patch: ClientPatch = {
        ...(body.name === undefined ? {} : { name: body.name }),
        ...(body.archived === undefined ? {} : { archived: body.archived }),
      };
      const result = await updateClient({ clients }, principal, {
        clientId: params.clientId,
        patch,
      });
      return result.ok ? json(200, toClientDetailDto(result.value)) : result.error;
    },
  );
}

export const updateClientHandler = createUpdateClientHandler();
