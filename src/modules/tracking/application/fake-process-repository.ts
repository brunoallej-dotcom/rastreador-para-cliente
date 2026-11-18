// In-memory fake of `ProcessRepository`, for the unit tests of the process use cases. It runs the
// real transitions of the aggregate (`startProcess`, `approveCurrentStage`, `applyProcessPatch`), keeps
// the real order (newest first, id breaking ties) and the real keyset paging, and mirrors the two rules
// the database decides: a title is unique among the ACTIVE processes of a client (F-80) and an archived
// client's processes are frozen (F-87), in the database's order of precedence. Imported by tests only.
import {
  ConflictError,
  err,
  NotFoundError,
  ok,
  ServiceUnavailableError,
  type DomainError,
  type Result,
} from '@/shared/kernel';
import { ClientArchivedError } from '../domain/errors';
import {
  applyProcessPatch,
  approveCurrentStage as applyApproval,
  startProcess,
  summarize,
  type Approver,
  type Process,
  type ProcessClient,
  type ProcessListQuery,
  type ProcessPage,
  type ProcessPatch,
} from '../domain/process';
import type { NewProcess, ProcessRepository } from '../domain/process-repository';
import type { StageTemplate } from '../domain/stage';

/** A client the fake knows: only what `create` needs to decide. */
export type FakeClient = ProcessClient & { readonly archived?: boolean };

export type FakeProcessRepository = ProcessRepository & {
  /** One entry per call, e.g. `create:<clientId>`, `find:<id>`, `update:<id>`, `approve:<id>`, `list:<clientId>`. */
  readonly calls: string[];
  /** The processes the fake holds right now. */
  readonly stored: () => readonly Process[];
  /** Makes every later call throw `ServiceUnavailableError` (E-21). */
  failWithOutage(): void;
  /** Makes `create`, `update` and `approve` answer `err(error)`, as the database would refuse them. */
  refuseWrites(error: DomainError): void;
};

export const FAKE_TEMPLATE: StageTemplate = {
  stages: [
    { position: 1, name: 'Contrato assinado', description: null },
    { position: 2, name: 'Briefing', description: 'Levantamento inicial' },
    { position: 3, name: 'Entrega final', description: null },
  ],
};

/** The CEO whose session the fake approves with (the database takes the approver from the session). */
export const FAKE_APPROVER: Approver = {
  userId: '11111111-1111-4111-8111-111111111111',
  displayName: 'CEO',
  role: 'ceo',
  aal: 'aal2',
};

/**
 * The key two titles are compared by (spec §3.7.1, §3.7.2): NFKC, lower case, without the invisible
 * variation marks and with every run of spaces reduced to one. The database index does the same.
 */
const INVISIBLE_VARIATION_MARKS = /[\u034F\u180B-\u180F\uFE00-\uFE0F\u{E0100}-\u{E01EF}]/gu;
const SPACE_RUNS = /[ \u1680]+/g;
export const titleKey = (title: string): string =>
  title
    .normalize('NFKC')
    .toLowerCase()
    .replace(INVISIBLE_VARIATION_MARKS, '')
    .replace(SPACE_RUNS, ' ');

const FAKE_ID_PREFIX = '00000000-0000-4000-8000-';
const ID_DIGITS = 12;
const fakeId = (n: number) => `${FAKE_ID_PREFIX}${String(n).padStart(ID_DIGITS, '0')}`;
const MS_PER_MINUTE = 60_000;
const NEW_PROCESS_ID_BASE = 900;
const NEW_STAGE_ID_BASE = 5000;

/** Newest first, then `id` ascending: the order of the database query. */
function compareForList(a: Process, b: Process): number {
  const byDate = b.createdAt.getTime() - a.createdAt.getTime();
  if (byDate !== 0) return byDate;
  return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}

export function createFakeProcessRepository(
  options: {
    readonly clients?: readonly FakeClient[];
    readonly processes?: readonly Process[];
    readonly template?: StageTemplate;
    readonly now?: Date;
    /** Who the fake's session is when it approves. Default: `FAKE_APPROVER`. */
    readonly approver?: Approver;
  } = {},
): FakeProcessRepository {
  const clients = new Map((options.clients ?? []).map((client) => [client.id, client]));
  const rows = new Map((options.processes ?? []).map((process) => [process.id, process]));
  const template = options.template ?? FAKE_TEMPLATE;
  const now = options.now ?? new Date('2026-06-01T12:00:00.000Z');
  const approver = options.approver ?? FAKE_APPROVER;
  const calls: string[] = [];
  let outage = false;
  let refusal: DomainError | null = null;
  let created = 0;
  let stagesCreated = 0;

  const guard = () => {
    if (outage) throw new ServiceUnavailableError('the database is down');
  };

  /** Is another ACTIVE process of the client already called `title` (by key)? */
  const titleTaken = (clientId: string, title: string, exceptId?: string): boolean =>
    [...rows.values()].some(
      (other) =>
        other.clientId === clientId &&
        other.id !== exceptId &&
        other.status === 'active' &&
        titleKey(other.title) === titleKey(title),
    );

  /** F-87: the processes of an archived client are frozen. */
  const frozen = (process: Process): boolean => clients.get(process.clientId)?.archived === true;

  return {
    calls,
    stored: () => [...rows.values()],
    failWithOutage: () => void (outage = true),
    refuseWrites: (error) => void (refusal = error),

    create(input: NewProcess): Promise<Result<Process, DomainError>> {
      calls.push(`create:${input.clientId}`);
      guard();
      if (refusal !== null) return Promise.resolve(err(refusal));
      const client = clients.get(input.clientId);
      if (client === undefined) {
        return Promise.resolve(err(new NotFoundError('no such client')));
      }
      if (client.archived === true) return Promise.resolve(err(new ClientArchivedError()));
      if (titleTaken(client.id, input.title)) {
        return Promise.resolve(err(new ConflictError('the title is already active in the client')));
      }

      created += 1;
      const started = startProcess({
        id: fakeId(NEW_PROCESS_ID_BASE + created),
        client: { id: client.id, name: client.name },
        title: input.title,
        stages: input.stages ?? template.stages,
        at: new Date(now.getTime() + created * MS_PER_MINUTE),
        newStageId: () => fakeId(NEW_STAGE_ID_BASE + ++stagesCreated),
      });
      if (!started.ok) return Promise.resolve(started);
      rows.set(started.value.id, started.value);
      return Promise.resolve(ok(started.value));
    },

    find(processId) {
      calls.push(`find:${processId}`);
      guard();
      return Promise.resolve(rows.get(processId) ?? null);
    },

    update(processId, patch: ProcessPatch): Promise<Result<Process, DomainError>> {
      calls.push(`update:${processId}`);
      guard();
      if (refusal !== null) return Promise.resolve(err(refusal));
      const current = rows.get(processId);
      if (current === undefined) {
        return Promise.resolve(err(new NotFoundError('no such process')));
      }
      // The database's order: not found, archived client, not active (inside the patch), title taken.
      if (frozen(current)) return Promise.resolve(err(new ClientArchivedError()));
      const next = applyProcessPatch(current, patch, now);
      if (
        next.ok &&
        next.value.status === 'active' &&
        titleTaken(current.clientId, next.value.title, current.id)
      ) {
        return Promise.resolve(err(new ConflictError('the title is already active in the client')));
      }
      if (next.ok) rows.set(processId, next.value);
      return Promise.resolve(next);
    },

    approve(processId, expectedStageId): Promise<Result<Process, DomainError>> {
      calls.push(`approve:${processId}`);
      guard();
      if (refusal !== null) return Promise.resolve(err(refusal));
      const current = rows.get(processId);
      if (current === undefined) {
        return Promise.resolve(err(new NotFoundError('no such process')));
      }
      if (frozen(current)) return Promise.resolve(err(new ClientArchivedError()));
      const next = applyApproval(current, { expectedStageId, approver, at: now });
      if (next.ok) rows.set(processId, next.value);
      return Promise.resolve(next);
    },

    listByClient(clientId, query: ProcessListQuery): Promise<ProcessPage | null> {
      calls.push(`list:${clientId}`);
      guard();
      if (!clients.has(clientId)) return Promise.resolve(null);

      const ordered = [...rows.values()]
        .filter((process) => process.clientId === clientId)
        .filter((process) => query.status === undefined || process.status === query.status)
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
        items: items.map(summarize),
        next:
          rest.length > query.limit && last !== undefined
            ? { createdAt: last.createdAt.toISOString(), id: last.id }
            : null,
      });
    },

    defaultStageTemplate() {
      calls.push('template');
      guard();
      return Promise.resolve(template);
    },
  };
}
