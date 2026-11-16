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
 * `create` and `update` when Postgres rolled the transaction back (deadlock, serialization failure:
 * nothing was written, repeating is safe). A 503 from a write does not say whether it was saved:
 * repeating `update` is safe, repeating `create` can make a second process (spec §6, E-21). A
 * refusal by the database comes back as an `err` of the matching domain error (spec §3.7):
 * `ForbiddenError` (42501: the pipeline should have stopped this caller), `NotFoundError`,
 * `ValidationError`, `ClientArchivedError` or `ProcessNotActiveError`. `list` throws a
 * `ValidationError` on `query.cursor` when the database cannot read the position it was given.
 */
export interface ProcessRepository {
  /**
   * Creates an active process with its stages, the first one in progress, and returns it as it is
   * stored. `err(NotFoundError)` when the client does not exist; `err(ClientArchivedError)` when it
   * is archived (E-16): nothing is created then.
   */
  create(input: NewProcess): Promise<Result<Process, DomainError>>;

  /** `null` when the process does not exist (or the session cannot see it). */
  find(processId: string): Promise<Process | null>;

  /**
   * Applies the patch and returns the process as it is afterwards. `err(NotFoundError)` when the
   * process does not exist; `err(ProcessNotActiveError)` when it is completed or cancelled.
   */
  update(processId: string, patch: ProcessPatch): Promise<Result<Process, DomainError>>;

  /**
   * One page of the processes of a client, newest first (`created_at` descending, then `id`
   * ascending), or `null` when the client does not exist (or the session cannot see it).
   */
  listByClient(clientId: string, query: ProcessListQuery): Promise<ProcessPage | null>;

  /** The default stages, in order (Q-01). */
  defaultStageTemplate(): Promise<StageTemplate>;
}
