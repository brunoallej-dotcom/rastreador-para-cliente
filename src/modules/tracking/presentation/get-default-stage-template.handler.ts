import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { getDefaultStageTemplate } from '../application/get-default-stage-template';
import { createSupabaseProcessRepository } from '../infrastructure/supabase-process-repository';
import { PROCESS_READ_RULE } from './process-rate-limits';
import { toStageTemplateDto } from './process.dto';

/**
 * `GET /admin/stage-templates/default` (operationId `getDefaultStageTemplate`). Policy equal to the
 * contract: role ceo only, `allowPending: []`, user 300 / min in the `reads` counter. It takes no
 * parameter, query or body.
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createGetDefaultStageTemplateHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [PROCESS_READ_RULE],
    },
    async ({ request, requestId, cookies, logger, principal }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });
      const processes = createSupabaseProcessRepository(supabase, { logger });

      const result = await getDefaultStageTemplate({ processes }, principal);
      return result.ok ? json(200, toStageTemplateDto(result.value)) : result.error;
    },
  );
}

export const getDefaultStageTemplateHandler = createGetDefaultStageTemplateHandler();
