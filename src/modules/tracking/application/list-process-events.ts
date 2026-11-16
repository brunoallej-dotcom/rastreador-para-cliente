import {
  err,
  ForbiddenError,
  NotFoundError,
  ok,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { ProcessEventPage, ProcessEventQuery } from '../domain/process-event';
import type { ProcessEventQueries } from '../domain/process-event-queries';

export type ListProcessEventsDeps = { readonly events: ProcessEventQueries };

export type ListProcessEventsInput = {
  readonly processId: string;
  readonly query: ProcessEventQuery;
};

/**
 * `GET /admin/processes/{processId}/events` (RF-12, AC-28): one page of the timeline of a process for
 * a CEO, oldest first, each event with the actor (id and display name). A process that does not exist
 * is `NotFoundError` (404). The limit and the position were validated at the edge.
 */
export async function listProcessEvents(
  deps: ListProcessEventsDeps,
  principal: Principal,
  input: ListProcessEventsInput,
): Promise<Result<ProcessEventPage, DomainError>> {
  if (principal.role !== 'ceo') {
    return err(new ForbiddenError('only a CEO reads the timeline', { detail: 'Access denied.' }));
  }
  const page = await deps.events.list(input.processId, input.query);
  if (page === null) {
    return err(new NotFoundError('process not found', { detail: 'Process not found.' }));
  }
  return ok(page);
}
