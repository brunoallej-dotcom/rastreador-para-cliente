import { getRequestSupabase } from '@/shared/db/server-client';
import { json, pageQuerySchema, withRoute, type WithRoute } from '@/shared/http';
import { listMyProcesses } from '../application/list-my-processes';
import type { ProcessListPosition } from '../domain/process';
import { createSupabaseClientProcessQueries } from '../infrastructure/supabase-client-process-queries';
import { MY_PROCESS_READ_RULE } from './my-process-rate-limits';
import { decodeMyProcessCursor } from './my-process.cursor';
import { toMyProcessListDto } from './my-process.dto';

/**
 * `GET /me/processes` (operationId `listMyProcesses`). Policy equal to the contract: role client only,
 * `allowPending: []` (a login that still has to change its temporary password is a 403), user 300 / min
 * in the `reads` counter. The query is `limit` and `cursor` and nothing else: there is no client id
 * to send, so `?clientId=` is a 400. The tenant is the principal's, never an input (SEC-03).
 *
 * The cursor is decoded here, after the pipeline validated the query: a cursor that is tampered,
 * truncated, foreign (another endpoint's) or just not ours is a 400 `VALIDATION_ERROR` (E-29).
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createListMyProcessesHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['client'],
      allowPending: [],
      rateLimit: [MY_PROCESS_READ_RULE],
      query: pageQuerySchema,
    },
    async ({ request, requestId, cookies, logger, principal, query }) => {
      let after: ProcessListPosition | undefined;
      if (query.cursor !== undefined) {
        const decoded = decodeMyProcessCursor(query.cursor);
        if (!decoded.ok) return decoded.error;
        after = decoded.value;
      }

      const supabase = getRequestSupabase({ request, cookies, requestId });
      const queries = createSupabaseClientProcessQueries(supabase, { logger });

      const result = await listMyProcesses({ queries }, principal, {
        query: { limit: query.limit, ...(after === undefined ? {} : { after }) },
      });
      return result.ok ? json(200, toMyProcessListDto(result.value)) : result.error;
    },
  );
}

export const listMyProcessesHandler = createListMyProcessesHandler();
