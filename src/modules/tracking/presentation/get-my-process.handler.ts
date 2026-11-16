import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { getMyProcess } from '../application/get-my-process';
import { createSupabaseClientProcessQueries } from '../infrastructure/supabase-client-process-queries';
import { MY_PROCESS_READ_RULE } from './my-process-rate-limits';
import { toMyProcessDetailDto } from './my-process.dto';
import { processIdParamsSchema } from './process.schema';

/**
 * `GET /me/processes/{processId}` (operationId `getMyProcess`). Policy equal to the contract: role
 * client only, `allowPending: []`, user 300 / min in the `reads` counter. A malformed id is a 400
 * (E-06); an id that is another client's and one that does not exist are the same 404 (E-05). The
 * tenant is the principal's, never an input (SEC-03).
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createGetMyProcessHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['client'],
      allowPending: [],
      rateLimit: [MY_PROCESS_READ_RULE],
      params: processIdParamsSchema,
    },
    async ({ request, requestId, cookies, logger, principal, params }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });
      const queries = createSupabaseClientProcessQueries(supabase, { logger });

      const result = await getMyProcess({ queries }, principal, { processId: params.processId });
      return result.ok ? json(200, toMyProcessDetailDto(result.value)) : result.error;
    },
  );
}

export const getMyProcessHandler = createGetMyProcessHandler();
