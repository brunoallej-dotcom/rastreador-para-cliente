import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { approveCurrentStage } from '../application/approve-current-stage';
import { createSupabaseProcessRepository } from '../infrastructure/supabase-process-repository';
import { approveStageBodySchema } from './approve-stage.schema';
import { PROCESS_WRITE_RULE } from './process-rate-limits';
import { toProcessDetailDto } from './process.dto';
import { processIdParamsSchema } from './process.schema';

/**
 * `POST /admin/processes/{processId}/approvals` (operationId `approveCurrentStage`). Policy equal to
 * the contract: role ceo only, `allowPending: []`, user 60 / min in the `writes` counter. The "Ok" of a
 * CEO: completes the current stage and starts the next (or completes the process). A missing process
 * is a 404, a completed or cancelled one a 422 `PROCESS_NOT_ACTIVE`, an expected stage that is no
 * longer the current one a 409 `STALE_STAGE` carrying `currentStageId`.
 *
 * Retrying after a 503 never approves twice: if the first call was saved, the retry is 409
 * `STALE_STAGE` (the next stage is current now) or, after the last stage, 422 `PROCESS_NOT_ACTIVE`
 * (E-02, spec §3.7.3); the CEO reads the process to see what the first call did.
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createApproveCurrentStageHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [PROCESS_WRITE_RULE],
      params: processIdParamsSchema,
      body: approveStageBodySchema,
    },
    async ({ request, requestId, cookies, logger, principal, params, body }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });
      const processes = createSupabaseProcessRepository(supabase, { logger });

      const result = await approveCurrentStage({ processes }, principal, {
        processId: params.processId,
        expectedStageId: body.expectedStageId,
      });
      return result.ok ? json(200, toProcessDetailDto(result.value)) : result.error;
    },
  );
}

export const approveCurrentStageHandler = createApproveCurrentStageHandler();
