import {
  err,
  ForbiddenError,
  NotFoundError,
  ok,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { ProcessListQuery, ProcessPage } from '../domain/process';
import type { ProcessRepository } from '../domain/process-repository';

export type ListClientProcessesDeps = { readonly processes: ProcessRepository };

export type ListClientProcessesInput = {
  readonly clientId: string;
  readonly query: ProcessListQuery;
};

/**
 * `GET /admin/clients/{clientId}/processes` (RF-09, AC-15): one page of the processes of a client
 * for a CEO, newest first, with the current stage and the progress of each. A client that does not
 * exist is `NotFoundError` (404). The limit, the status filter and the position were validated at
 * the edge.
 */
export async function listClientProcesses(
  deps: ListClientProcessesDeps,
  principal: Principal,
  input: ListClientProcessesInput,
): Promise<Result<ProcessPage, DomainError>> {
  if (principal.role !== 'ceo') {
    return err(new ForbiddenError('only a CEO lists processes', { detail: 'Access denied.' }));
  }
  const page = await deps.processes.listByClient(input.clientId, input.query);
  if (page === null) {
    return err(new NotFoundError('client not found', { detail: 'Client not found.' }));
  }
  return ok(page);
}
