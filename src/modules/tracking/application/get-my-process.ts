import {
  err,
  NotFoundError,
  ok,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { ClientProcessQueries, MyProcessDetail } from '../domain/client-process-queries';
import { requireClientTenant } from './my-tenant';

export type GetMyProcessDeps = { readonly queries: ClientProcessQueries };

export type GetMyProcessInput = { readonly processId: string };

/**
 * `GET /me/processes/{processId}` (RF-13, AC-20): one process of the client of the session, with its
 * stages. A process of another client and one that does not exist are the same `NotFoundError`
 * (404, E-05): the query is filtered by the tenant of the session, so the first is never read, and
 * nothing in the answer tells the two apart.
 */
export async function getMyProcess(
  deps: GetMyProcessDeps,
  principal: Principal,
  input: GetMyProcessInput,
): Promise<Result<MyProcessDetail, DomainError>> {
  const tenant = requireClientTenant(principal);
  if (!tenant.ok) return tenant;

  const process = await deps.queries.find(tenant.value, input.processId);
  if (process === null) {
    return err(new NotFoundError('process not found', { detail: 'Process not found.' }));
  }
  return ok(process);
}
