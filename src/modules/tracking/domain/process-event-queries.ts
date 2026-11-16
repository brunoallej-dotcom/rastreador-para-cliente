import type { ProcessEventPage, ProcessEventQuery } from './process-event';

/**
 * The read side of the process timeline, as a query service of its own (not the repository of the
 * aggregate): it reads the audit trail, the stages and the profiles of the CURRENT request's session,
 * so the database decides what the session may read (RLS: only a CEO reads `audit_events`).
 *
 * Every method throws `ServiceUnavailableError` when the database is slow or down (E-21) and a
 * `ValidationError` on `query.cursor` when the database cannot read the position it was given.
 */
export interface ProcessEventQueries {
  /**
   * One page of the events of a process, oldest first (ascending id), or `null` when the process does
   * not exist (or the session cannot see it).
   */
  list(processId: string, query: ProcessEventQuery): Promise<ProcessEventPage | null>;
}
