// In-memory fake of `ClientRepository`, for the unit tests of the client use cases. It keeps the
// real order (newest first, id breaking ties) and the real keyset paging. Imported by tests only.
import {
  err,
  ok,
  NotFoundError,
  ServiceUnavailableError,
  type DomainError,
  type Result,
} from '@/shared/kernel';
import type { Client, ClientListQuery, ClientPage, ClientPatch } from '../domain/client';
import type { ClientRepository } from '../domain/client-repository';

export type FakeClientRepository = ClientRepository & {
  /** One entry per call, e.g. `create:Nome`, `find:<id>`, `update:<id>`, `list`. */
  readonly calls: string[];
  /** The clients the fake holds right now. */
  readonly clients: () => readonly Client[];
  /** Makes every later call throw `ServiceUnavailableError` (E-21). */
  failWithOutage(): void;
  /** Makes `create` and `update` answer `err(error)`, as the database would refuse them. */
  refuseWrites(error: DomainError): void;
};

const FAKE_ID_PREFIX = '00000000-0000-4000-8000-';
const ID_DIGITS = 12;
const fakeId = (n: number) => `${FAKE_ID_PREFIX}${String(n).padStart(ID_DIGITS, '0')}`;
const MS_PER_MINUTE = 60_000;

/** Newest first, then `id` ascending: the order of the database query. */
function compareForList(a: Client, b: Client): number {
  const byDate = b.createdAt.getTime() - a.createdAt.getTime();
  if (byDate !== 0) return byDate;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

export function createFakeClientRepository(
  initial: readonly Client[] = [],
  options: { readonly now?: Date } = {},
): FakeClientRepository {
  const rows = new Map(initial.map((client) => [client.id, client]));
  const calls: string[] = [];
  let outage = false;
  let refusal: DomainError | null = null;
  let created = 0;
  const now = options.now ?? new Date('2026-06-01T12:00:00.000Z');

  const guard = () => {
    if (outage) throw new ServiceUnavailableError('the database is down');
  };

  return {
    calls,
    clients: () => [...rows.values()],
    failWithOutage: () => void (outage = true),
    refuseWrites: (error) => void (refusal = error),

    create(name): Promise<Result<Client, DomainError>> {
      calls.push(`create:${name}`);
      guard();
      if (refusal !== null) return Promise.resolve(err(refusal));
      created += 1;
      const createdAt = new Date(now.getTime() + created * MS_PER_MINUTE);
      const client: Client = {
        id: fakeId(created),
        name,
        archivedAt: null,
        activeProcessCount: 0,
        processCount: 0,
        createdAt,
        updatedAt: createdAt,
      };
      rows.set(client.id, client);
      return Promise.resolve(ok(client));
    },

    find(clientId) {
      calls.push(`find:${clientId}`);
      guard();
      return Promise.resolve(rows.get(clientId) ?? null);
    },

    update(clientId, patch: ClientPatch): Promise<Result<Client, DomainError>> {
      calls.push(`update:${clientId}`);
      guard();
      if (refusal !== null) return Promise.resolve(err(refusal));
      const current = rows.get(clientId);
      if (current === undefined) {
        return Promise.resolve(err(new NotFoundError('no such client')));
      }
      const { archived } = patch;
      const next: Client = {
        ...current,
        name: patch.name ?? current.name,
        archivedAt:
          archived === undefined
            ? current.archivedAt
            : archived
              ? (current.archivedAt ?? now)
              : null,
        updatedAt: now,
      };
      rows.set(clientId, next);
      return Promise.resolve(ok(next));
    },

    list(query: ClientListQuery): Promise<ClientPage> {
      calls.push('list');
      guard();
      const ordered = [...rows.values()]
        .filter((client) => query.includeArchived || client.archivedAt === null)
        .sort(compareForList);
      const afterPosition = query.after;
      const rest =
        afterPosition === undefined
          ? ordered
          : ordered.filter((client) => {
              const position = new Date(afterPosition.createdAt).getTime();
              const date = client.createdAt.getTime();
              return date < position || (date === position && client.id > afterPosition.id);
            });
      const items = rest.slice(0, query.limit);
      const last = items.at(-1);
      const hasMore = rest.length > query.limit;
      return Promise.resolve({
        items,
        next:
          hasMore && last !== undefined
            ? { createdAt: last.createdAt.toISOString(), id: last.id }
            : null,
      });
    },
  };
}
