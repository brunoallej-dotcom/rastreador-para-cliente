import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { getProcess } from '../application/get-process';
import { createSupabaseProcessRepository } from '../infrastructure/supabase-process-repository';
import { PROCESS_READ_RULE } from './process-rate-limits';
import { toProcessDetailDto } from './process.dto';
import { processIdParamsSchema } from './process.schema';

/**
 * `GET /admin/processes/{processId}` (operationId `getProcess`). Policy equal to the contract: role
 * ceo only, `allowPending: []`, user 300 / min in the `reads` counter. A malformed id is a 400, an
 * unknown one a 404.
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createGetProcessHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [PROCESS_READ_RULE],
      params: processIdParamsSchema,
    },
    async ({ request, requestId, cookies, logger, principal, params }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });
      const processes = createSupabaseProcessRepository(supabase, { logger });

      const result = await getProcess({ processes }, principal, { processId: params.processId });
      return result.ok ? json(200, toProcessDetailDto(result.value)) : result.error;
    },
  );
}

export const getProcessHandler = createGetProcessHandler();
