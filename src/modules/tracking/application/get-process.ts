import {
  err,
  ForbiddenError,
  NotFoundError,
  ok,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { Process } from '../domain/process';
import type { ProcessRepository } from '../domain/process-repository';

export type GetProcessDeps = { readonly processes: ProcessRepository };

export type GetProcessInput = { readonly processId: string };

/**
 * `GET /admin/processes/{processId}` (RF-09, AC-15): a CEO reads one process with its stages, the
 * approvals and the client. A process that does not exist is `NotFoundError` (404).
 */
export async function getProcess(
  deps: GetProcessDeps,
  principal: Principal,
  input: GetProcessInput,
): Promise<Result<Process, DomainError>> {
  if (principal.role !== 'ceo') {
    return err(new ForbiddenError('only a CEO reads processes', { detail: 'Access denied.' }));
  }
  const process = await deps.processes.find(input.processId);
  if (process === null) {
    return err(new NotFoundError('process not found', { detail: 'Process not found.' }));
  }
  return ok(process);
}
