/**
 * What the timeline of a process may show (the contract's `ProcessEventAction`). The audit trail has
 * more actions (clients, accounts); a process timeline carries only these, so a new audit action never
 * reaches a CEO's timeline until someone adds it here and to the contract.
 */
export const PROCESS_EVENT_ACTIONS = [
  'process.created',
  'process.updated',
  'process.cancelled',
  'process.completed',
  'stage.approved',
] as const;
export type ProcessEventAction = (typeof PROCESS_EVENT_ACTIONS)[number];

/** Who did it: a CEO, by id and display name (the contract's `ActorRef`). */
export type ProcessEventActor = {
  readonly id: string;
  readonly displayName: string;
};

/**
 * What an event says about the stage it concerns (`ProcessEventDetails`). It never carries a title:
 * the audit metadata of `process.updated` has none (SEC-16, spec §3.7.2), and the process title read
 * today would be wrong after a later rename, so `previousTitle` and `newTitle` are not part of this
 * type at all.
 */
export type ProcessEventDetails = {
  readonly stageId?: string;
  readonly stagePosition?: number;
  readonly stageName?: string;
};

/** One line of the timeline, mapped from the audit trail and the stage and profile rows. */
export type ProcessEvent = {
  /** The sequential id of the audit event (a `bigint`, kept as the decimal text). */
  readonly id: string;
  readonly occurredAt: Date;
  readonly action: ProcessEventAction;
  /** `null` for an action with no actor on record (a system action). */
  readonly actor: ProcessEventActor | null;
  readonly details: ProcessEventDetails;
};

/**
 * Where a page of the timeline stops: the id of its last event. The timeline is read in ascending id
 * order, and that is the order the writes happened in: every write of one process takes the process
 * row lock first, so a later event always has a larger id (spec §3.7.3).
 */
export type ProcessEventPosition = {
  readonly id: string;
};

export type ProcessEventQuery = {
  readonly limit: number;
  /** The page starts right after this position; absent for the first page. */
  readonly after?: ProcessEventPosition;
};

/** `next` is `null` on the last page. */
export type ProcessEventPage = {
  readonly items: readonly ProcessEvent[];
  readonly next: ProcessEventPosition | null;
};
