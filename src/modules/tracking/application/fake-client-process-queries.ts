// In-memory fake of `ClientProcessQueries`, for the unit tests of the client panel use cases. It keeps
// the real order (newest first, id breaking ties), the real keyset paging and, above all, the tenant
// filter: a process of another client is never returned, by id or in a page. Imported by tests only.
import { ServiceUnavailableError } from '@/shared/kernel';
import type {
  ClientProcessQueries,
  MyProcessDetail,
  MyProcessListQuery,
  MyProcessPage,
  MyProcessSummary,
} from '../domain/client-process-queries';

/** A process the fake holds, with the tenant it belongs to (which the read model does not carry). */
export type StoredMyProcess = {
  readonly clientId: string;
  readonly process: MyProcessDetail;
};

export type FakeClientProcessQueries = ClientProcessQueries & {
  /** One entry per call, e.g. `list:<clientId>`, `find:<clientId>:<processId>`. */
  readonly calls: string[];
  /** Makes every later call throw `ServiceUnavailableError` (E-21). */
  failWithOutage(): void;
};

/** The summary a list row shows: the detail without its stages. */
function summaryOf(process: MyProcessDetail): MyProcessSummary {
  const { stages: _stages, ...summary } = process;
  return summary;
}

/** Newest first, then `id` ascending: the order of the database query. */
function compareForList(a: MyProcessDetail, b: MyProcessDetail): number {
  const byDate = b.createdAt.getTime() - a.createdAt.getTime();
  if (byDate !== 0) return byDate;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

export function createFakeClientProcessQueries(
  stored: readonly StoredMyProcess[],
): FakeClientProcessQueries {
  const calls: string[] = [];
  let outage = false;
  const guard = () => {
    if (outage) throw new ServiceUnavailableError('the database is down');
  };

  return {
    calls,
    failWithOutage: () => void (outage = true),

    list(clientId, query: MyProcessListQuery): Promise<MyProcessPage> {
      calls.push(`list:${clientId}`);
      guard();
      const ordered = stored
        .filter((entry) => entry.clientId === clientId)
        .map((entry) => entry.process)
        .sort(compareForList);
      const afterPosition = query.after;
      const rest =
        afterPosition === undefined
          ? ordered
          : ordered.filter((process) => {
              const position = new Date(afterPosition.createdAt).getTime();
              const date = process.createdAt.getTime();
              return date < position || (date === position && process.id > afterPosition.id);
            });
      const items = rest.slice(0, query.limit);
      const last = items.at(-1);
      return Promise.resolve({
        items: items.map(summaryOf),
        next:
          rest.length > query.limit && last !== undefined
            ? { createdAt: last.createdAt.toISOString(), id: last.id }
            : null,
      });
    },

    find(clientId, processId): Promise<MyProcessDetail | null> {
      calls.push(`find:${clientId}:${processId}`);
      guard();
      const found = stored.find(
        (entry) => entry.clientId === clientId && entry.process.id === processId,
      );
      return Promise.resolve(found?.process ?? null);
    },
  };
}
