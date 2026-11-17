import { getRequestSupabase } from '@/shared/db/server-client';
import { json, pageQuerySchema, withRoute, type WithRoute } from '@/shared/http';
import { listProcessEvents } from '../application/list-process-events';
import type { ProcessEventPosition } from '../domain/process-event';
import { createSupabaseProcessEventQueries } from '../infrastructure/supabase-process-event-queries';
import { PROCESS_READ_RULE } from './process-rate-limits';
import { decodeProcessEventCursor } from './process-events.cursor';
import { toProcessEventListDto } from './process-events.dto';
import { processIdParamsSchema } from './process.schema';

/**
 * `GET /admin/processes/{processId}/events` (operationId `listProcessEvents`). Policy equal to the
 * contract: role ceo only, `allowPending: []`, user 300 / min in the `reads` counter. The timeline of
 * the process, oldest first. An unknown process is a 404.
 *
 * The cursor is decoded here, after the pipeline validated the query: a cursor that is tampered,
 * truncated, foreign (another endpoint's) or just not ours is a 400 `VALIDATION_ERROR` (E-29).
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createListProcessEventsHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [PROCESS_READ_RULE],
      params: processIdParamsSchema,
      query: pageQuerySchema,
    },
    async ({ request, requestId, cookies, principal, params, query }) => {
      let after: ProcessEventPosition | undefined;
      if (query.cursor !== undefined) {
        const decoded = decodeProcessEventCursor(query.cursor);
        if (!decoded.ok) return decoded.error;
        after = decoded.value;
      }

      const supabase = getRequestSupabase({ request, cookies, requestId });
      const events = createSupabaseProcessEventQueries(supabase);

      const result = await listProcessEvents({ events }, principal, {
        processId: params.processId,
        query: { limit: query.limit, ...(after === undefined ? {} : { after }) },
      });
      return result.ok ? json(200, toProcessEventListDto(result.value)) : result.error;
    },
  );
}

export const listProcessEventsHandler = createListProcessEventsHandler();
