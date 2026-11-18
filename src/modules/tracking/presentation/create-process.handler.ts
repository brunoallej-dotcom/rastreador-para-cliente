import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { createProcess } from '../application/create-process';
import { createSupabaseProcessRepository } from '../infrastructure/supabase-process-repository';
import { clientIdParamsSchema } from './client.schema';
import { PROCESS_WRITE_RULE } from './process-rate-limits';
import { toProcessDetailDto } from './process.dto';
import { createProcessBodySchema, toStageInputs } from './process.schema';

const CREATED = 201;
const PROCESSES_PATH = '/api/v1/admin/processes';

/**
 * `POST /admin/clients/{clientId}/processes` (operationId `createProcess`). Policy equal to the
 * contract: role ceo only, `allowPending: []`, user 60 / min in the `writes` counter. Answers 201 with
 * the new process and a `Location` header that points at it.
 *
 * A 503 does not say whether the process was saved, but a repeated request does not make a SECOND
 * process while the first is active: the title is unique among the active processes of the client, so
 * the repetition of a saved request is 409 `CONFLICT` and the CEO lists the client's processes (spec
 * §3.7.2, §6, E-21, E-98, F-80). If the first one was completed or cancelled in between, its title is
 * free again and the repetition creates another. An archived client is 422 `CLIENT_ARCHIVED` (E-16).
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createCreateProcessHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [PROCESS_WRITE_RULE],
      params: clientIdParamsSchema,
      body: createProcessBodySchema,
    },
    async ({ request, requestId, cookies, logger, principal, params, body }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });
      const processes = createSupabaseProcessRepository(supabase, { logger });

      const result = await createProcess({ processes }, principal, {
        clientId: params.clientId,
        title: body.title,
        ...(body.stages === undefined ? {} : { stages: toStageInputs(body.stages) }),
      });
      if (!result.ok) return result.error;

      return json(CREATED, toProcessDetailDto(result.value), {
        headers: { Location: `${PROCESSES_PATH}/${result.value.id}` },
      });
    },
  );
}

export const createProcessHandler = createCreateProcessHandler();
