import { ok, type DomainError, type Principal, type Result } from '@/shared/kernel';
import type {
  ClientProcessQueries,
  MyProcessListQuery,
  MyProcessPage,
} from '../domain/client-process-queries';
import { requireClientTenant, type PanelLogger } from './my-tenant';

export type ListMyProcessesDeps = {
  readonly queries: ClientProcessQueries;
  readonly logger: PanelLogger;
};

export type ListMyProcessesInput = { readonly query: MyProcessListQuery };

/**
 * `GET /me/processes` (RF-13, AC-20): one page of the processes of the client of the session, newest
 * first, with the current stage and the progress of each. The tenant is the principal's `clientId`;
 * the input has no client id and the use case takes none (SEC-03). The limit and the position were
 * validated at the edge. A client with no process gets an empty page.
 *
 * The read leaves a trail (F-99): `tracking.client_panel_list` with how many processes the page held and
 * whether it was a later page, never a title or a name.
 */
export async function listMyProcesses(
  deps: ListMyProcessesDeps,
  principal: Principal,
  input: ListMyProcessesInput,
): Promise<Result<MyProcessPage, DomainError>> {
  const tenant = requireClientTenant(principal, deps.logger);
  if (!tenant.ok) return tenant;

  const page = await deps.queries.list(tenant.value, input.query);
  deps.logger.info(
    {
      event: 'tracking.client_panel_list',
      count: page.items.length,
      paged: input.query.after !== undefined,
    },
    'tracking.client_panel_list',
  );
  return ok(page);
}
