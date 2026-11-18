import type { DomainError, Result } from '@/shared/kernel';
import type { Process, ProcessListQuery, ProcessPage, ProcessPatch } from './process';
import type { StageDraft, StageTemplate } from './stage';

/** What `create` needs: the client, the title and the stages (or the template). */
export type NewProcess = {
  readonly clientId: string;
  /** Already validated and normalized. */
  readonly title: string;
  /** `null`: the default template. Otherwise 1 to 30 stages, already validated (I1). */
  readonly stages: readonly StageDraft[] | null;
};

/**
 * Processes of the CURRENT request's session (the database decides what the session may do: reads
 * by RLS, writes by `SECURITY DEFINER` functions that check the CEO role, `aal2` and the TOTP
 * factor).
 *
 * Every method throws `ServiceUnavailableError` when the database is slow or down (E-21); so do
 * `create`, `update` and `approve` when Postgres rolled the transaction back (deadlock, serialization
 * failure: nothing was written, repeating is safe). A 503 from a write does not say whether it was
 * saved: repeating a rename is idempotent, repeating a cancel that was saved is
 * `ProcessNotActiveError`, repeating `create` that was saved is a `ConflictError` (the title is already
 * active in the client: it never makes a second process, F-80), and repeating an approval that was
 * saved is `StaleStageError` (or `ProcessNotActiveError` after the last stage): it never approves twice
 * (spec §3.7.3, E-02, E-21). A refusal by the database comes back as an `err` of the matching domain
 * error (spec §3.7): `ForbiddenError` (42501: the pipeline should have stopped this caller),
 * `NotFoundError`, `ValidationError`, `ClientArchivedError` (create, update and approve: an archived
 * client takes no new process and its processes are frozen, F-87), `ProcessNotActiveError`,
 * `ConflictError` (create and update: the title is already active in the client, F-80) or
 * `StaleStageError`. `list` throws a `ValidationError` on `query.cursor` when the database cannot
 * read the position it was given.
 */
export interface ProcessRepository {
  /**
   * Creates an active process with its stages, the first one in progress, and returns it as it is
   * stored. `err(NotFoundError)` when the client does not exist; `err(ClientArchivedError)` when it
   * is archived (E-16): nothing is created then; `err(ConflictError)` when an active process of the
   * client already has the title (same key as client names: case, spaces and Unicode compatibility
   * forms do not make it different, F-80, E-96): nothing is created then either.
   */
  create(input: NewProcess): Promise<Result<Process, DomainError>>;

  /** `null` when the process does not exist (or the session cannot see it). */
  find(processId: string): Promise<Process | null>;

  /**
   * Applies the patch and returns the process as it is afterwards. `err(NotFoundError)` when the
   * process does not exist; `err(ClientArchivedError)` when its client is archived (frozen: F-87,
   * E-99; this wins over the status); `err(ProcessNotActiveError)` when it is completed or
   * cancelled; `err(ConflictError)` when the new title is already an active process's of the same
   * client (a rename together with a cancellation does not contest it, E-97).
   */
  update(processId: string, patch: ProcessPatch): Promise<Result<Process, DomainError>>;

  /**
   * The CEO's "Ok" (RF-10, I6): completes the current stage if `expectedStageId` is still the current
   * one, starts the next stage (or completes the process after the last), and returns the process as
   * it is afterwards. The approver is the signed-in CEO, which the database takes from the session
   * and not from an argument. Atomic and audited by the database, which locks the process row
   * BEFORE it looks at the status or the stage (F-82), so of several simultaneous approvals of the
   * same stage exactly one wins. `err(NotFoundError)` when the process does not exist;
   * `err(ClientArchivedError)` when its client is archived (frozen: F-87, E-99; this wins over the
   * status and over a stale stage); `err(ProcessNotActiveError)` when it is completed or cancelled
   * (this wins over a stale stage: E-03); `err(StaleStageError)`, carrying the id of the stage that is current now, when
   * `expectedStageId` is not the current stage (E-01, E-02). A state the database refuses to write
   * (`INVARIANT_VIOLATION`: a broken row it checked its own writes against, T-49) is not a domain
   * error: it throws an unexpected error (500) and nothing was written.
   */
  approve(processId: string, expectedStageId: string): Promise<Result<Process, DomainError>>;

  /**
   * One page of the processes of a client, newest first (`created_at` descending, then `id`
   * ascending), or `null` when the client does not exist (or the session cannot see it).
   */
  listByClient(clientId: string, query: ProcessListQuery): Promise<ProcessPage | null>;

  /** The default stages, in order (Q-01). */
  defaultStageTemplate(): Promise<StageTemplate>;
}
