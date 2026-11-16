import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { listClients } from '../application/list-clients';
import type { ClientListPosition } from '../domain/client';
import { createSupabaseClientRepository } from '../infrastructure/supabase-client-repository';
import { CLIENT_READ_RULE } from './client-rate-limits';
import { decodeClientCursor } from './client.cursor';
import { toClientListDto } from './client.dto';
import { listClientsQuerySchema } from './client.schema';

/**
 * `GET /admin/clients` (operationId `listClients`). Policy equal to the contract: role ceo only,
 * `allowPending: []` (no pending action at all, which is how the pipeline asks for `aal2` and a
 * verified factor), user 300 / min in the `reads` counter.
 *
 * The cursor is decoded here, after the pipeline validated the query: a cursor that is tampered,
 * truncated, foreign (another endpoint's) or just not ours is a 400 `VALIDATION_ERROR` (E-29).
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createListClientsHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [CLIENT_READ_RULE],
      query: listClientsQuerySchema,
    },
    async ({ request, requestId, cookies, logger, principal, query }) => {
      let after: ClientListPosition | undefined;
      if (query.cursor !== undefined) {
        const decoded = decodeClientCursor(query.cursor);
        if (!decoded.ok) return decoded.error;
        after = decoded.value;
      }

      const supabase = getRequestSupabase({ request, cookies, requestId });
      const clients = createSupabaseClientRepository(supabase, { logger });

      const result = await listClients({ clients }, principal, {
        limit: query.limit,
        includeArchived: query.includeArchived,
        ...(after === undefined ? {} : { after }),
      });
      return result.ok ? json(200, toClientListDto(result.value)) : result.error;
    },
  );
}

export const listClientsHandler = createListClientsHandler();
