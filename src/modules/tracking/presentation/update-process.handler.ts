import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { updateProcess } from '../application/update-process';
import { createSupabaseProcessRepository } from '../infrastructure/supabase-process-repository';
import { PROCESS_WRITE_RULE } from './process-rate-limits';
import { toProcessDetailDto } from './process.dto';
import { processIdParamsSchema, toProcessPatch, updateProcessBodySchema } from './process.schema';

/**
 * `PATCH /admin/processes/{processId}` (operationId `updateProcess`). Policy equal to the contract:
 * role ceo only, `allowPending: []`, user 60 / min in the `writes` counter. Renames and/or cancels
 * (`status: "cancelled"`, the only manual transition) an ACTIVE process; any other one is a 422
 * `PROCESS_NOT_ACTIVE`. Repeating a PATCH is safe.
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createUpdateProcessHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [PROCESS_WRITE_RULE],
      params: processIdParamsSchema,
      body: updateProcessBodySchema,
    },
    async ({ request, requestId, cookies, logger, principal, params, body }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });
      const processes = createSupabaseProcessRepository(supabase, { logger });

      const result = await updateProcess({ processes }, principal, {
        processId: params.processId,
        patch: toProcessPatch(body),
      });
      return result.ok ? json(200, toProcessDetailDto(result.value)) : result.error;
    },
  );
}

export const updateProcessHandler = createUpdateProcessHandler();
