import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { listClientProcesses } from '../application/list-client-processes';
import type { ProcessListPosition } from '../domain/process';
import { createSupabaseProcessRepository } from '../infrastructure/supabase-process-repository';
import { clientIdParamsSchema } from './client.schema';
import { PROCESS_READ_RULE } from './process-rate-limits';
import { decodeProcessCursor } from './process.cursor';
import { toProcessListDto } from './process.dto';
import { listClientProcessesQuerySchema } from './process.schema';

/**
 * `GET /admin/clients/{clientId}/processes` (operationId `listClientProcesses`). Policy equal to the
 * contract: role ceo only, `allowPending: []`, user 300 / min in the `reads` counter. An unknown client
 * is a 404; a client with no process is an empty page.
 *
 * The cursor is decoded here, after the pipeline validated the query: a cursor that is tampered,
 * truncated, foreign (another endpoint's) or just not ours is a 400 `VALIDATION_ERROR` (E-29).
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createListClientProcessesHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [PROCESS_READ_RULE],
      params: clientIdParamsSchema,
      query: listClientProcessesQuerySchema,
    },
    async ({ request, requestId, cookies, logger, principal, params, query }) => {
      let after: ProcessListPosition | undefined;
      if (query.cursor !== undefined) {
        const decoded = decodeProcessCursor(query.cursor);
        if (!decoded.ok) return decoded.error;
        after = decoded.value;
      }

      const supabase = getRequestSupabase({ request, cookies, requestId });
      const processes = createSupabaseProcessRepository(supabase, { logger });

      const result = await listClientProcesses({ processes }, principal, {
        clientId: params.clientId,
        query: {
          limit: query.limit,
          ...(query.status === undefined ? {} : { status: query.status }),
          ...(after === undefined ? {} : { after }),
        },
      });
      return result.ok ? json(200, toProcessListDto(result.value)) : result.error;
    },
  );
}

export const listClientProcessesHandler = createListClientProcessesHandler();
