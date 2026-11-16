import {
  err,
  ForbiddenError,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import { requireProcessChange, type Process, type ProcessPatch } from '../domain/process';
import type { ProcessRepository } from '../domain/process-repository';

export type UpdateProcessDeps = { readonly processes: ProcessRepository };

export type UpdateProcessInput = {
  readonly processId: string;
  /** `title` is already validated and normalized; a missing field is left alone. */
  readonly patch: ProcessPatch;
};

/**
 * `PATCH /admin/processes/{processId}` (RF-11, AC-19): renames and/or cancels an ACTIVE process. A
 * completed or cancelled one answers `ProcessNotActiveError` (422, I3, I4); a missing one,
 * `NotFoundError` (404); a patch that changes nothing, `ValidationError` (400).
 */
export async function updateProcess(
  deps: UpdateProcessDeps,
  principal: Principal,
  input: UpdateProcessInput,
): Promise<Result<Process, DomainError>> {
  if (principal.role !== 'ceo') {
    return err(new ForbiddenError('only a CEO updates processes', { detail: 'Access denied.' }));
  }
  const patch = requireProcessChange(input.patch);
  if (!patch.ok) return patch;
  return deps.processes.update(input.processId, patch.value);
}
