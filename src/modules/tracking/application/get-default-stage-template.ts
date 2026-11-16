import {
  err,
  ForbiddenError,
  ok,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { ProcessRepository } from '../domain/process-repository';
import type { StageTemplate } from '../domain/stage';

export type GetDefaultStageTemplateDeps = { readonly processes: ProcessRepository };

/**
 * `GET /admin/stage-templates/default` (RF-08): the stages a new process gets when the CEO sends
 * none. Changed only by migration (Q-01).
 */
export async function getDefaultStageTemplate(
  deps: GetDefaultStageTemplateDeps,
  principal: Principal,
): Promise<Result<StageTemplate, DomainError>> {
  if (principal.role !== 'ceo') {
    return err(new ForbiddenError('only a CEO reads the template', { detail: 'Access denied.' }));
  }
  return ok(await deps.processes.defaultStageTemplate());
}
