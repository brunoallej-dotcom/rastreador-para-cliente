import {
  err,
  ForbiddenError,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { Process } from '../domain/process';
import type { ProcessRepository } from '../domain/process-repository';
import { validateStageInputs, type StageDraft, type StageInput } from '../domain/stage';

export type CreateProcessDeps = { readonly processes: ProcessRepository };

export type CreateProcessInput = {
  readonly clientId: string;
  /** Already validated and normalized (NFC, trimmed, 1 to 160 visible characters). */
  readonly title: string;
  /** 1 to 30 stages in order; absent: the default template (AC-15). */
  readonly stages?: readonly StageInput[];
};

/**
 * `POST /admin/clients/{clientId}/processes` (RF-08, AC-15): a CEO creates an active process for a
 * client, with the stages sent or with the default template; the first stage starts in progress. The
 * pipeline already checked the role and `aal2`; the role is checked again here as the rule of the use
 * case, and the database function checks it a third time (spec §3.5). I1 is checked here too (1 to 30
 * stages, E-20), before the round trip. A client that does not exist is `NotFoundError` (404) and an
 * archived one is `ClientArchivedError` (422, E-16), and a title that an active process of the client
 * already has is `ConflictError` (409, F-80, E-96): all decided by the database in the same
 * transaction that creates the process, so repeating a request whose answer was lost makes no second
 * process while the first one is active (once it is completed or cancelled its title is free again).
 */
export async function createProcess(
  deps: CreateProcessDeps,
  principal: Principal,
  input: CreateProcessInput,
): Promise<Result<Process, DomainError>> {
  if (principal.role !== 'ceo') {
    return err(new ForbiddenError('only a CEO creates processes', { detail: 'Access denied.' }));
  }

  let stages: readonly StageDraft[] | null = null;
  if (input.stages !== undefined) {
    const valid = validateStageInputs(input.stages);
    if (!valid.ok) return valid;
    stages = valid.value;
  }
  return deps.processes.create({ clientId: input.clientId, title: input.title, stages });
}
