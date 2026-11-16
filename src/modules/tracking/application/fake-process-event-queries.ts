// In-memory fake of `ProcessEventQueries`, for the unit tests of the timeline use case. It keeps the
// real order (ascending id) and the real keyset paging. Imported by tests only.
import { ServiceUnavailableError } from '@/shared/kernel';
import type { ProcessEvent, ProcessEventPage, ProcessEventQuery } from '../domain/process-event';
import type { ProcessEventQueries } from '../domain/process-event-queries';

export type FakeProcessEventQueries = ProcessEventQueries & {
  /** One entry per call: `list:<processId>`. */
  readonly calls: string[];
  /** Makes every later call throw `ServiceUnavailableError` (E-21). */
  failWithOutage(): void;
};

/** The events of the processes the fake knows; a process it does not know is not there. */
export function createFakeProcessEventQueries(
  processes: Readonly<Record<string, readonly ProcessEvent[]>>,
): FakeProcessEventQueries {
  const calls: string[] = [];
  let outage = false;

  return {
    calls,
    failWithOutage: () => void (outage = true),

    list(processId: string, query: ProcessEventQuery): Promise<ProcessEventPage | null> {
      calls.push(`list:${processId}`);
      if (outage) return Promise.reject(new ServiceUnavailableError('the database is down'));
      const events = processes[processId];
      if (events === undefined) return Promise.resolve(null);

      const afterId = query.after === undefined ? null : BigInt(query.after.id);
      const rest = [...events]
        .sort((a, b) => (BigInt(a.id) < BigInt(b.id) ? -1 : 1))
        .filter((event) => afterId === null || BigInt(event.id) > afterId);
      const items = rest.slice(0, query.limit);
      const last = items.at(-1);
      return Promise.resolve({
        items,
        next: rest.length > query.limit && last !== undefined ? { id: last.id } : null,
      });
    },
  };
}
