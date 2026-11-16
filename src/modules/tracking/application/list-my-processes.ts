import { ok, type DomainError, type Principal, type Result } from '@/shared/kernel';
import type {
  ClientProcessQueries,
  MyProcessListQuery,
  MyProcessPage,
} from '../domain/client-process-queries';
import { requireClientTenant } from './my-tenant';

export type ListMyProcessesDeps = { readonly queries: ClientProcessQueries };

export type ListMyProcessesInput = { readonly query: MyProcessListQuery };

/**
 * `GET /me/processes` (RF-13, AC-20): one page of the processes of the client of the session, newest
 * first, with the current stage and the progress of each. The tenant is the principal's `clientId`;
 * the input has no client id and the use case takes none (SEC-03). The limit and the position were
 * validated at the edge. A client with no process gets an empty page.
 */
export async function listMyProcesses(
  deps: ListMyProcessesDeps,
  principal: Principal,
  input: ListMyProcessesInput,
): Promise<Result<MyProcessPage, DomainError>> {
  const tenant = requireClientTenant(principal);
  if (!tenant.ok) return tenant;

  return ok(await deps.queries.list(tenant.value, input.query));
}
