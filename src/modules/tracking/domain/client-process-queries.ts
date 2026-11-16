import type { InvariantViolation, ProcessListPosition, ProcessStatus } from './process';
import type { StageStatus } from './stage';

/**
 * What a client sees of its own processes (spec §3.6.1, RF-13): the read side of the panel, apart
 * from the `Process` aggregate (spec §3.2, "query service"). It carries ONLY what the contract's
 * `MyProcess*` schemas carry: no `version`, no `clientId`, no stage or CEO ids, no approval, no
 * `cancelledAt`. Whatever is not here cannot reach the response, whoever maps it.
 */

/** The stage in progress (the contract's `MyCurrentStage`). */
export type MyCurrentStage = {
  readonly position: number;
  readonly name: string;
};

/** A stage as the client sees it (`MyStage`): where it is, never who approved it. */
export type MyStage = {
  readonly position: number;
  readonly name: string;
  readonly description: string | null;
  readonly status: StageStatus;
  readonly startedAt: Date | null;
  readonly completedAt: Date | null;
};

/** One row of the client's list (`MyProcessSummary`). */
export type MyProcessSummary = {
  readonly id: string;
  readonly title: string;
  readonly status: ProcessStatus;
  /** The stage `in_progress`, whatever the status of the process (where a cancelled one stopped). */
  readonly currentStage: MyCurrentStage | null;
  readonly totalStages: number;
  readonly completedStages: number;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly completedAt: Date | null;
};

/** `MyProcessDetail`: the summary and every stage, in position order. */
export type MyProcessDetail = MyProcessSummary & {
  readonly stages: readonly MyStage[];
};

export type MyProcessListQuery = {
  readonly limit: number;
  /** The page starts right after this position; absent for the first page. */
  readonly after?: ProcessListPosition;
};

/** `next` is `null` on the last page. */
export type MyProcessPage = {
  readonly items: readonly MyProcessSummary[];
  readonly next: ProcessListPosition | null;
};

/**
 * The read side of the client panel, as the signed-in client (RLS applies to it). `clientId` is the
 * tenant of the SESSION (`principal.clientId`): it is never a value the caller sent. A process of
 * another client, or one that does not exist, is `null` and indistinguishable (E-05).
 *
 * Every method throws `ServiceUnavailableError` when the database is slow or down (E-21), and a plain
 * error (500) for a row it does not understand, one that breaks an invariant (a process with no
 * stage), or one that is not the tenant's: the panel never shows corrupt data, nor another client's.
 * `list` throws a `ValidationError` on `query.cursor` when the database cannot read the position.
 */
export interface ClientProcessQueries {
  /** One page of the tenant's processes, newest first (`created_at` descending, then `id` ascending). */
  list(clientId: string, query: MyProcessListQuery): Promise<MyProcessPage>;

  /** The tenant's process with its stages, or `null` when the tenant has no such process. */
  find(clientId: string, processId: string): Promise<MyProcessDetail | null>;
}

/**
 * The progress a client sees, a whole number from 0 to 100: the completed stages over all of them,
 * rounded to the nearest integer (1 of 3 is 33, 2 of 3 is 67). With at most 30 stages, 100 happens
 * only when every stage is completed. The contract names the field and its range, not the rounding.
 */
export function progressPercent(
  summary: Pick<MyProcessSummary, 'completedStages' | 'totalStages'>,
): number {
  if (summary.totalStages <= 0) return 0;
  return Math.round((100 * summary.completedStages) / summary.totalStages);
}

/** Where a stage status sits in the order a process walks them: done, then current, then waiting. */
const WALK_ORDER: Readonly<Record<StageStatus, number>> = {
  completed: 0,
  in_progress: 1,
  pending: 2,
};

/**
 * What `summaryViolations` cannot see in a process whose stages are all there: the positions must be
 * contiguous from 1 (I1) and the stages walked in order, completed ones, then at most one in
 * progress, then pending ones (I2, I4). The client panel cannot check I5 (the approvals are not
 * readable by a client), so the whole check is this and `summaryViolations` over the counters.
 */
export function stageOrderViolations(
  stages: readonly Pick<MyStage, 'position' | 'status'>[],
): readonly InvariantViolation[] {
  const found: InvariantViolation[] = [];
  if (stages.some((stage, index) => stage.position !== index + 1)) {
    found.push({ invariant: 'I1', message: 'the stage positions are not contiguous from 1 to n' });
  }
  const inProgress = stages.filter((stage) => stage.status === 'in_progress').length;
  const ranks = stages.map((stage) => WALK_ORDER[stage.status]);
  const walkedInOrder = ranks.every(
    (rank, index) => index === 0 || (ranks[index - 1] ?? rank) <= rank,
  );
  if (inProgress > 1 || !walkedInOrder) {
    found.push({ invariant: 'I2', message: 'the stages are not walked in order' });
  }
  return found;
}
