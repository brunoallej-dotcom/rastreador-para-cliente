import {
  err,
  NotFoundError,
  ok,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { ClientProcessQueries, MyProcessDetail } from '../domain/client-process-queries';
import { requireClientTenant, type PanelLogger } from './my-tenant';

export type GetMyProcessDeps = {
  readonly queries: ClientProcessQueries;
  readonly logger: PanelLogger;
};

export type GetMyProcessInput = { readonly processId: string };

/**
 * `GET /me/processes/{processId}` (RF-13, AC-20): one process of the client of the session, with its
 * stages. A process of another client and one that does not exist are the same `NotFoundError`
 * (404, E-05): the query is filtered by the tenant of the session, so the first is never read, and
 * nothing in the answer tells the two apart (and nothing is logged for either: the trail below is only
 * for what was shown).
 *
 * A successful read leaves a trail (F-99): `tracking.client_panel_read` with the process id, never a title
 * or a name. With the `requestId` of the line and the user of the access line it says who read what.
 */
export async function getMyProcess(
  deps: GetMyProcessDeps,
  principal: Principal,
  input: GetMyProcessInput,
): Promise<Result<MyProcessDetail, DomainError>> {
  const tenant = requireClientTenant(principal, deps.logger);
  if (!tenant.ok) return tenant;

  const process = await deps.queries.find(tenant.value, input.processId);
  if (process === null) {
    return err(new NotFoundError('process not found', { detail: 'Process not found.' }));
  }
  deps.logger.info(
    { event: 'tracking.client_panel_read', processId: process.id },
    'tracking.client_panel_read',
  );
  return ok(process);
}
