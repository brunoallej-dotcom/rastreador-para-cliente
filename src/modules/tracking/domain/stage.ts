import { err, ok, ValidationError, type Result, type ValidationIssue } from '@/shared/kernel';

/** `pending` -> `in_progress` -> `completed` (spec §1.3). */
export const STAGE_STATUSES = ['pending', 'in_progress', 'completed'] as const;
export type StageStatus = (typeof STAGE_STATUSES)[number];

/** I1: a process has from 1 to 30 stages. */
export const MIN_STAGES_PER_PROCESS = 1;
export const MAX_STAGES_PER_PROCESS = 30;
export const STAGE_NAME_MAX_LENGTH = 120;
export const STAGE_DESCRIPTION_MAX_LENGTH = 2000;

/** The CEO who gave the "Ok" of a stage (the contract's `ActorRef`). */
export type StageApprover = {
  readonly id: string;
  readonly displayName: string;
};

/** I5: a `completed` stage has exactly one approval, with the CEO and the instant. */
export type StageApproval = {
  readonly approvedBy: StageApprover;
  readonly approvedAt: Date;
};

export type Stage = {
  readonly id: string;
  /** From 1 to the number of stages, with no gap (I1). */
  readonly position: number;
  readonly name: string;
  readonly description: string | null;
  readonly status: StageStatus;
  readonly startedAt: Date | null;
  readonly completedAt: Date | null;
  /** Set exactly when `status` is `completed` (I5). */
  readonly approval: StageApproval | null;
};

/**
 * A stage as the caller describes it when it creates a process. `description` may be missing or
 * `null` (no description).
 */
export type StageInput = {
  readonly name: string;
  readonly description?: string | null;
};

/** A stage ready to be stored: the description is text or `null`, never missing. */
export type StageDraft = {
  readonly name: string;
  readonly description: string | null;
};

/** One entry of the default stage template (`default_stage_template`, Q-01). */
export type StageTemplateItem = {
  readonly position: number;
  readonly name: string;
  readonly description: string | null;
};

export type StageTemplate = {
  readonly stages: readonly StageTemplateItem[];
};

const codePointLength = (text: string) => Array.from(text).length;

/**
 * I1 for a list of stages the caller sent: from 1 to 30 of them (E-20), each with a name of 1 to 120
 * characters and a description of up to 2000. Which characters a name may hold (control characters,
 * invisible fillers, "at least one letter or number") is the rule of the edge validator and of the
 * database (E-30), not of the aggregate. Every problem is collected, with the path the 400 shows.
 */
export function validateStageInputs(
  stages: readonly StageInput[],
): Result<readonly StageDraft[], ValidationError> {
  const issues: ValidationIssue[] = [];
  if (stages.length < MIN_STAGES_PER_PROCESS || stages.length > MAX_STAGES_PER_PROCESS) {
    issues.push({
      path: 'body.stages',
      message: `Must have from ${MIN_STAGES_PER_PROCESS} to ${MAX_STAGES_PER_PROCESS} stages`,
    });
  }
  stages.forEach((stage, index) => {
    const nameLength = codePointLength(stage.name.trim());
    if (nameLength < 1 || nameLength > STAGE_NAME_MAX_LENGTH) {
      issues.push({
        path: `body.stages[${index}].name`,
        message: `Must have from 1 to ${STAGE_NAME_MAX_LENGTH} characters`,
      });
    }
    if (
      stage.description !== undefined &&
      stage.description !== null &&
      codePointLength(stage.description) > STAGE_DESCRIPTION_MAX_LENGTH
    ) {
      issues.push({
        path: `body.stages[${index}].description`,
        message: `Must have at most ${STAGE_DESCRIPTION_MAX_LENGTH} characters`,
      });
    }
  });
  if (issues.length > 0) return err(new ValidationError('invalid stages', issues));

  return ok(stages.map((stage) => ({ name: stage.name, description: stage.description ?? null })));
}
