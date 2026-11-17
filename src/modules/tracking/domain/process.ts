import {
  err,
  ForbiddenError,
  ok,
  ValidationError,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import { ProcessNotActiveError, StaleStageError } from './errors';
import {
  MAX_STAGES_PER_PROCESS,
  MIN_STAGES_PER_PROCESS,
  validateStageInputs,
  type Stage,
  type StageInput,
  type StageStatus,
} from './stage';

/**
 * `active` -> `completed` (the last approval) or `cancelled` (a CEO cancels). Both end states are
 * final (spec §3.6).
 */
export const PROCESS_STATUSES = ['active', 'completed', 'cancelled'] as const;
export type ProcessStatus = (typeof PROCESS_STATUSES)[number];

/** `processes.title` has 1 to 160 characters after trimming (spec §4.1, contract `CreateProcessRequest`). */
export const PROCESS_TITLE_MAX_LENGTH = 160;

/** The client a process belongs to, as the CEO panel shows it. */
export type ProcessClient = {
  readonly id: string;
  readonly name: string;
};

/**
 * The `Process` aggregate (spec §3.6): the process and its stages, which only change together. The
 * invariants I1 to I6 are checked by `invariantViolations` and kept by the transitions below
 * (`startProcess`, `approveCurrentStage`, `applyProcessPatch`); the database keeps the same ones
 * with constraints and with the functions that are the only way to write (spec §3.7).
 */
export type Process = {
  readonly id: string;
  readonly clientId: string;
  readonly client: ProcessClient;
  readonly title: string;
  readonly status: ProcessStatus;
  /** Starts at 1 and grows by one at each mutation. */
  readonly version: number;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  /** Set exactly when `status` is `completed` (I3). */
  readonly completedAt: Date | null;
  /** Set exactly when `status` is `cancelled` (I4). */
  readonly cancelledAt: Date | null;
  /** In position order. */
  readonly stages: readonly Stage[];
};

/** The stage that is `in_progress` (what the panel calls "the current stage"). */
export type CurrentStage = Pick<Stage, 'id' | 'position' | 'name'>;

/**
 * One row of the process list of a client (the contract's `ProcessSummary`): the process without its
 * stages, with what the list needs of them.
 */
export type ProcessSummary = {
  readonly id: string;
  readonly clientId: string;
  readonly title: string;
  readonly status: ProcessStatus;
  readonly currentStage: CurrentStage | null;
  readonly totalStages: number;
  readonly completedStages: number;
  readonly version: number;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly completedAt: Date | null;
  readonly cancelledAt: Date | null;
};

/**
 * The stage that is `in_progress`, whatever the status of the process: in an active process it is
 * the current one, in a cancelled one it is where the process stopped (I4 freezes the stages as they
 * are), and a completed process has none.
 */
export function currentStageOf(process: Pick<Process, 'stages'>): CurrentStage | null {
  const stage = process.stages.find((candidate) => candidate.status === 'in_progress');
  return stage === undefined ? null : { id: stage.id, position: stage.position, name: stage.name };
}

export function completedStageCount(process: Pick<Process, 'stages'>): number {
  return process.stages.filter((stage) => stage.status === 'completed').length;
}

export function summarize(process: Process): ProcessSummary {
  return {
    id: process.id,
    clientId: process.clientId,
    title: process.title,
    status: process.status,
    currentStage: currentStageOf(process),
    totalStages: process.stages.length,
    completedStages: completedStageCount(process),
    version: process.version,
    createdAt: process.createdAt,
    updatedAt: process.updatedAt,
    completedAt: process.completedAt,
    cancelledAt: process.cancelledAt,
  };
}

// ------------------------------------------------------------------------------ invariants ----

export type Invariant = 'I1' | 'I2' | 'I3' | 'I4' | 'I5';

export type InvariantViolation = {
  readonly invariant: Invariant;
  readonly message: string;
};

/** Where a stage status sits in the order a process walks them: done, then current, then waiting. */
const STAGE_ORDER: Readonly<Record<StageStatus, number>> = {
  completed: 0,
  in_progress: 1,
  pending: 2,
};

/** Completed stages, then at most one in progress, then pending ones: never out of that order. */
function isWalkedInOrder(stages: readonly Stage[]): boolean {
  const inProgress = stages.filter((stage) => stage.status === 'in_progress').length;
  if (inProgress > 1) return false;
  const ranks = stages.map((stage) => STAGE_ORDER[stage.status]);
  return ranks.every((rank, index) => index === 0 || (ranks[index - 1] ?? rank) <= rank);
}

/**
 * Everything wrong with the aggregate as a snapshot (I6 is about a transition, see
 * `approveCurrentStage`). An empty list is a healthy process.
 * - I1: from 1 to 30 stages, `position` contiguous from 1 to n.
 * - I2: `active` has exactly one `in_progress` stage, the ones before it `completed` and the ones
 *   after it `pending`, and neither `completedAt` nor `cancelledAt`.
 * - I3: `completed` has every stage `completed` and `completedAt` (and no `cancelledAt`).
 * - I4: `cancelled` has `cancelledAt` (and no `completedAt`) and its stages are as they were when it
 *   stopped: still walked in order, with at most one `in_progress`. That nothing changes after the
 *   cancellation is what the transitions guarantee: all of them refuse a cancelled process.
 * - I5: a `completed` stage has an approval and no other stage has one.
 */
export function invariantViolations(process: Process): readonly InvariantViolation[] {
  const found: InvariantViolation[] = [];
  const add = (invariant: Invariant, message: string) => found.push({ invariant, message });
  const { stages } = process;

  if (stages.length < MIN_STAGES_PER_PROCESS || stages.length > MAX_STAGES_PER_PROCESS) {
    add('I1', `a process has from ${MIN_STAGES_PER_PROCESS} to ${MAX_STAGES_PER_PROCESS} stages`);
  }
  if (stages.some((stage, index) => stage.position !== index + 1)) {
    add('I1', 'the stage positions are not contiguous from 1 to n');
  }

  const inProgress = stages.filter((stage) => stage.status === 'in_progress');
  switch (process.status) {
    case 'active':
      if (inProgress.length !== 1 || !isWalkedInOrder(stages)) {
        add('I2', 'an active process has exactly one stage in progress, after the completed ones');
      }
      if (process.completedAt !== null || process.cancelledAt !== null) {
        add('I2', 'an active process has neither completedAt nor cancelledAt');
      }
      break;
    case 'completed':
      if (stages.some((stage) => stage.status !== 'completed')) {
        add('I3', 'a completed process has every stage completed');
      }
      if (process.completedAt === null || process.cancelledAt !== null) {
        add('I3', 'a completed process has completedAt and no cancelledAt');
      }
      break;
    case 'cancelled':
      if (process.cancelledAt === null || process.completedAt !== null) {
        add('I4', 'a cancelled process has cancelledAt and no completedAt');
      }
      if (!isWalkedInOrder(stages)) {
        add('I4', 'the stages of a cancelled process stay as they were when it stopped');
      }
      break;
  }

  for (const stage of stages) {
    if ((stage.status === 'completed') !== (stage.approval !== null)) {
      add('I5', 'a stage has an approval exactly when it is completed');
      break;
    }
  }
  return found;
}

/**
 * What `summaryViolations` reads of a row: a `ProcessSummary` is one, and so is what the client panel
 * (which has no `version`, no `clientId` and no stage ids) derives from a row of its own.
 */
export type SummaryCounters = Pick<
  ProcessSummary,
  'status' | 'totalStages' | 'completedStages' | 'completedAt' | 'cancelledAt'
> & { readonly currentStage: Pick<CurrentStage, 'position'> | null };

/**
 * `invariantViolations` for a row of the list, which has no stages to look at: only what the summary
 * carries of them (how many there are, how many are completed, which one is current). It cannot see
 * everything the snapshot check sees (an out-of-order stage that keeps the counts right), but it
 * catches the corruption a list can show: no stage, a process whose progress does not add up, a state
 * without its date.
 * - I1: from 1 to 30 stages, and no more completed than there are.
 * - I2: `active` has a current stage, and exactly the stages before it are completed.
 * - I3: `completed` has every stage completed and no current stage.
 * - I4: `cancelled` stopped where its stages were: if one is current, the ones before it are completed.
 * - the dates: `completedAt` exactly when `completed`, `cancelledAt` exactly when `cancelled`.
 */
export function summaryViolations(summary: SummaryCounters): readonly InvariantViolation[] {
  const found: InvariantViolation[] = [];
  const add = (invariant: Invariant, message: string) => found.push({ invariant, message });
  const { totalStages, completedStages, currentStage } = summary;

  if (totalStages < MIN_STAGES_PER_PROCESS || totalStages > MAX_STAGES_PER_PROCESS) {
    add('I1', `a process has from ${MIN_STAGES_PER_PROCESS} to ${MAX_STAGES_PER_PROCESS} stages`);
  }
  if (completedStages > totalStages)
    add('I1', 'a process cannot have more completed stages than stages');

  const progressAddsUp =
    currentStage !== null &&
    currentStage.position <= totalStages &&
    completedStages === currentStage.position - 1;
  switch (summary.status) {
    case 'active':
      if (!progressAddsUp) {
        add('I2', 'an active process has a current stage, after exactly the completed ones');
      }
      if (summary.completedAt !== null || summary.cancelledAt !== null) {
        add('I2', 'an active process has neither completedAt nor cancelledAt');
      }
      break;
    case 'completed':
      if (completedStages !== totalStages || currentStage !== null) {
        add('I3', 'a completed process has every stage completed and no current stage');
      }
      if (summary.completedAt === null || summary.cancelledAt !== null) {
        add('I3', 'a completed process has completedAt and no cancelledAt');
      }
      break;
    case 'cancelled':
      if (currentStage !== null && !progressAddsUp) {
        add(
          'I4',
          'a cancelled process stopped after exactly the stages completed before the current one',
        );
      }
      if (summary.cancelledAt === null || summary.completedAt !== null) {
        add('I4', 'a cancelled process has cancelledAt and no completedAt');
      }
      break;
  }
  return found;
}

// ------------------------------------------------------------------------------ transitions ----

export type StartProcessInput = {
  readonly id: string;
  readonly client: ProcessClient;
  /** Already validated and normalized. */
  readonly title: string;
  readonly stages: readonly StageInput[];
  readonly at: Date;
  /** Id of each new stage, asked once per stage in order. */
  readonly newStageId: () => string;
};

/**
 * `create_process` as a pure function: an active process, version 1, whose first stage is
 * `in_progress` since `at` and the others `pending` (I2). 1 to 30 stages, or a `ValidationError`
 * (I1, E-20).
 */
export function startProcess(input: StartProcessInput): Result<Process, ValidationError> {
  const drafts = validateStageInputs(input.stages);
  if (!drafts.ok) return drafts;

  return ok({
    id: input.id,
    clientId: input.client.id,
    client: input.client,
    title: input.title,
    status: 'active',
    version: 1,
    createdAt: input.at,
    updatedAt: input.at,
    completedAt: null,
    cancelledAt: null,
    stages: drafts.value.map((draft, index): Stage => ({
      id: input.newStageId(),
      position: index + 1,
      name: draft.name,
      description: draft.description,
      status: index === 0 ? 'in_progress' : 'pending',
      startedAt: index === 0 ? input.at : null,
      completedAt: null,
      approval: null,
    })),
  });
}

/** Who gives the "Ok": a CEO whose session is `aal2` (I6). */
export type Approver = Pick<Principal, 'userId' | 'displayName' | 'role' | 'aal'>;

export type ApproveStageInput = {
  /** The stage the caller saw as current (optimistic concurrency, `If-Match` semantics, I6). */
  readonly expectedStageId: string;
  readonly approver: Approver;
  readonly at: Date;
};

/**
 * The "Ok" (`approve_current_stage`, spec §3.6) as a pure function. I6: the approver must be a CEO
 * with `aal2` (`ForbiddenError`), the process must be `active` (`ProcessNotActiveError`, which wins
 * over a stale id: E-03) and `expectedStageId` must be the current stage (`StaleStageError` with the
 * id that is current, E-01, E-02). The current stage becomes `completed` with its approval; the next
 * one becomes `in_progress`, or, after the last, the process becomes `completed` (E-04).
 */
export function approveCurrentStage(
  process: Process,
  input: ApproveStageInput,
): Result<Process, DomainError> {
  const { approver, at } = input;
  if (approver.role !== 'ceo' || approver.aal !== 'aal2') {
    return err(new ForbiddenError('only a CEO with aal2 approves', { detail: 'Access denied.' }));
  }
  if (process.status !== 'active') return err(new ProcessNotActiveError());

  const current = process.stages.find((stage) => stage.status === 'in_progress');
  if (current === undefined) return err(new StaleStageError(null));
  if (current.id !== input.expectedStageId) return err(new StaleStageError(current.id));

  const stages = process.stages.map((stage): Stage => {
    if (stage.id === current.id) {
      return {
        ...stage,
        status: 'completed',
        completedAt: at,
        approval: {
          approvedBy: { id: approver.userId, displayName: approver.displayName },
          approvedAt: at,
        },
      };
    }
    if (stage.position === current.position + 1) {
      return { ...stage, status: 'in_progress', startedAt: at };
    }
    return stage;
  });
  const isLast = current.position === process.stages.length;

  return ok({
    ...process,
    stages,
    status: isLast ? 'completed' : 'active',
    completedAt: isLast ? at : null,
    version: process.version + 1,
    updatedAt: at,
  });
}

/**
 * What `PATCH /admin/processes/{processId}` may change: the title, and `cancel: true` (the only
 * manual transition; there is no way back, I4). A missing field is left alone.
 */
export type ProcessPatch = {
  readonly title?: string;
  readonly cancel?: true;
};

/**
 * A patch must change something (contract: `UpdateProcessRequest.minProperties: 1`). The database
 * function refuses the empty patch too; this check answers 400 before the round trip.
 */
export function requireProcessChange(patch: ProcessPatch): Result<ProcessPatch, ValidationError> {
  if (patch.title === undefined && patch.cancel === undefined) {
    return err(
      new ValidationError('the patch names no field', [
        { path: 'body', message: 'Must name at least one field to change' },
      ]),
    );
  }
  return ok(patch);
}

/**
 * `update_process` as a pure function. Only an `active` process changes (I3, I4: the others answer
 * `ProcessNotActiveError`, even to a rename that would change nothing). A patch that changes
 * nothing (the same title) returns the process as it is: no new version. Otherwise the version
 * grows by one, once, whether the patch renames, cancels or both. Cancelling leaves the stages as
 * they are (I4).
 */
export function applyProcessPatch(
  process: Process,
  patch: ProcessPatch,
  at: Date,
): Result<Process, DomainError> {
  const change = requireProcessChange(patch);
  if (!change.ok) return change;
  if (process.status !== 'active') return err(new ProcessNotActiveError());

  const renamed = patch.title !== undefined && patch.title !== process.title;
  const cancelling = patch.cancel === true;
  if (!renamed && !cancelling) return ok(process);

  return ok({
    ...process,
    title: patch.title !== undefined && renamed ? patch.title : process.title,
    status: cancelling ? 'cancelled' : process.status,
    cancelledAt: cancelling ? at : process.cancelledAt,
    version: process.version + 1,
    updatedAt: at,
  });
}

// ------------------------------------------------------------------------------ listing ----

/**
 * Where a page of a client's process list stops: the `created_at` and `id` of its last row, the
 * keyset of the order the list uses (newest first, `id` breaking ties). `createdAt` is the exact text
 * the database sent (microsecond precision): a `Date` would round it to milliseconds.
 */
export type ProcessListPosition = {
  readonly createdAt: string;
  readonly id: string;
};

export type ProcessListQuery = {
  readonly limit: number;
  /** The page starts right after this position; absent for the first page. */
  readonly after?: ProcessListPosition;
  /** Only the processes in this status; absent for all of them. */
  readonly status?: ProcessStatus;
};

/** `next` is `null` on the last page. */
export type ProcessPage = {
  readonly items: readonly ProcessSummary[];
  readonly next: ProcessListPosition | null;
};
