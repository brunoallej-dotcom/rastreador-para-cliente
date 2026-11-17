import {
  err,
  ForbiddenError,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { Process } from '../domain/process';
import type { ProcessRepository } from '../domain/process-repository';

export type ApproveCurrentStageDeps = { readonly processes: ProcessRepository };

export type ApproveCurrentStageInput = {
  readonly processId: string;
  /** The stage the caller saw as current (optimistic concurrency, `If-Match` semantics, I6). */
  readonly expectedStageId: string;
};

/**
 * `POST /admin/processes/{processId}/approvals` (RF-10, AC-16 to AC-18): the "Ok" of a CEO. The
 * current stage becomes `completed` and the next one `in_progress`; after the last stage the process
 * is `completed` (E-04). One CEO is enough. The rules are those of the aggregate's pure transition
 * (`approveCurrentStage` in `domain/process.ts`), enforced atomically by the database function behind
 * the repository, which is the only thing that decides under concurrency (F-82).
 *
 * The answers, by precedence (E-01 to E-04, spec §3.7.3):
 * - a missing process is `NotFoundError` (404);
 * - a completed or cancelled one is `ProcessNotActiveError` (422), whatever the expected stage;
 * - an expected stage that is not the current one is `StaleStageError` (409) with the current id.
 *
 * Retrying an approval that was saved never approves twice: it is `StaleStageError` (the next stage is
 * current now) or, after the last stage, `ProcessNotActiveError` (E-02).
 */
export async function approveCurrentStage(
  deps: ApproveCurrentStageDeps,
  principal: Principal,
  input: ApproveCurrentStageInput,
): Promise<Result<Process, DomainError>> {
  if (principal.role !== 'ceo') {
    return err(new ForbiddenError('only a CEO approves stages', { detail: 'Access denied.' }));
  }
  return deps.processes.approve(input.processId, input.expectedStageId);
}
