import type { SupabaseClient } from '@supabase/supabase-js';
import { z } from 'zod';
import type { Database } from '@/shared/db/database.types';
import { upstreamFailure } from '@/shared/db/upstream-errors';
import {
  err,
  ConflictError,
  ForbiddenError,
  NotFoundError,
  ok,
  ValidationError,
  type DomainError,
  type Result,
} from '@/shared/kernel';
import type { Logger } from '@/shared/observability/logger';
import type { Client, ClientListPosition, ClientPage, ClientPatch } from '../domain/client';
import type { ClientRepository } from '../domain/client-repository';

/** Postgres: `insufficient_privilege`, what the database functions raise for a denied caller. */
const INSUFFICIENT_PRIVILEGE = '42501';
/** Postgres: `raise_exception`, with the application code as the message (spec §3.7). */
const RAISE_EXCEPTION = 'P0001';
const CHECK_VIOLATION = '23514';
const STRING_DATA_RIGHT_TRUNCATION = '22001';
const UNIQUE_VIOLATION = '23505';
const NOT_FOUND_MESSAGE = 'NOT_FOUND';
const INVALID_INPUT_MESSAGE = 'INVALID_INPUT';

/**
 * Columns of the read, explicit (no `select *`): the client plus two counters taken from the
 * client's processes with PostgREST's embedded `count`. The same relation is embedded twice under
 * two aliases; the second one is narrowed to active processes by an embedded filter (see
 * `ACTIVE_PROCESSES_FILTER`). RLS applies to the embedded rows too.
 */
const CLIENT_SELECT =
  'id, name, archived_at, created_at, updated_at, all_processes:processes(count), active_processes:processes(count)';
/** The embedded filter that makes `active_processes` count only processes with status `active`. */
const ACTIVE_PROCESSES_STATUS_COLUMN = 'active_processes.status';

/** PostgREST sends timestamps as `2026-11-16T11:30:24.984084+00:00`: any precision, with an offset. */
const timestampSchema = z.iso.datetime({ offset: true });

/** A client as the database function returns it: no counters (a new or changed client is re-read). */
const clientRowSchema = z.object({
  id: z.guid(),
  name: z.string(),
  archived_at: timestampSchema.nullable(),
  created_at: timestampSchema,
  updated_at: timestampSchema,
});

/** What an embedded `count` looks like: a list with exactly one `{ count }`. */
const embeddedCountSchema = z.tuple([z.object({ count: z.number().int().nonnegative() })]);

const clientWithCountsRowSchema = clientRowSchema.extend({
  all_processes: embeddedCountSchema,
  active_processes: embeddedCountSchema,
});

type ClientRow = z.infer<typeof clientRowSchema>;
type ClientWithCountsRow = z.infer<typeof clientWithCountsRowSchema>;

type ClientCounters = Pick<Client, 'activeProcessCount' | 'processCount'>;

const toClient = (row: ClientRow, counters: ClientCounters): Client => ({
  id: row.id,
  name: row.name,
  archivedAt: row.archived_at === null ? null : new Date(row.archived_at),
  activeProcessCount: counters.activeProcessCount,
  processCount: counters.processCount,
  createdAt: new Date(row.created_at),
  updatedAt: new Date(row.updated_at),
});

const toClientWithCounts = (row: ClientWithCountsRow): Client =>
  toClient(row, {
    activeProcessCount: row.active_processes[0].count,
    processCount: row.all_processes[0].count,
  });

/** A row is read from the database as untrusted data: what does not match fails closed (500). */
function parseRows(data: unknown): ClientWithCountsRow[] {
  const parsed = z.array(clientWithCountsRowSchema).safeParse(data);
  if (!parsed.success) throw new Error('the clients table returned a row that is not understood');
  return parsed.data;
}

const NEW_CLIENT_COUNTERS: ClientCounters = { activeProcessCount: 0, processCount: 0 };

const invalidInput = (cause: unknown) =>
  new ValidationError(
    'the database refused the input',
    [{ path: 'body', message: 'Invalid input' }],
    { cause },
  );

export type ClientRepositoryOptions = {
  readonly logger: Pick<Logger, 'warn'>;
};

/**
 * `ClientRepository` over Supabase, as the signed-in user (the request-scoped client, never the
 * admin client): reads go through `from('clients')` and RLS, writes only through the
 * `create_client` and `update_client` functions, which check the CEO role, `aal2` and the TOTP
 * factor by themselves and write the audit event in the same transaction.
 *
 * Whatever comes back is validated with Zod. Database errors are mapped by the table of spec §3.7;
 * an unmapped one is an unexpected error (500) and a slow or dead database is a 503 (E-21).
 */
export function createSupabaseClientRepository(
  supabase: SupabaseClient<Database>,
  options: ClientRepositoryOptions,
): ClientRepository {
  /** The list query: the clients, with their counters, in the order the list uses. */
  const clientsQuery = (includeArchived: boolean) => {
    const query = supabase
      .from('clients')
      .select(CLIENT_SELECT)
      .eq(ACTIVE_PROCESSES_STATUS_COLUMN, 'active')
      // postgrest-js retries a GET with backoff on its own (about 7 s on a dead upstream): without
      // this the 5 s bound of E-21 would not hold.
      .retry(false);
    return includeArchived ? query : query.is('archived_at', null);
  };

  /** Maps what a write function raised. Returns the domain error, or throws for the unexpected. */
  function refusalOf(
    operation: 'create_client' | 'update_client',
    error: { code?: string; message: string },
    status: number,
  ): DomainError {
    if (error.code === INSUFFICIENT_PRIVILEGE) {
      // Layer 1 should have stopped this caller: a denial here means it was bypassed (spec §3.7).
      options.logger.warn({ event: 'authz.database_denied', operation }, 'authz.database_denied');
      return new ForbiddenError(`${operation} denied the caller`, { detail: 'Access denied.' });
    }
    if (error.code === RAISE_EXCEPTION && error.message === NOT_FOUND_MESSAGE) {
      return new NotFoundError(`${operation} found no such client`, {
        detail: 'Client not found.',
      });
    }
    if (
      (error.code === RAISE_EXCEPTION && error.message === INVALID_INPUT_MESSAGE) ||
      error.code === CHECK_VIOLATION ||
      error.code === STRING_DATA_RIGHT_TRUNCATION
    ) {
      return invalidInput(error);
    }
    if (error.code === UNIQUE_VIOLATION) {
      return new ConflictError(`${operation} hit a unique constraint`);
    }
    throw upstreamFailure(operation, error, status);
  }

  async function find(clientId: string): Promise<Client | null> {
    const { data, error, status } = await supabase
      .from('clients')
      .select(CLIENT_SELECT)
      .eq('id', clientId)
      .eq(ACTIVE_PROCESSES_STATUS_COLUMN, 'active')
      .retry(false)
      .maybeSingle();
    if (error) throw upstreamFailure('read the client', error, status);
    if (data === null) return null;

    const [row] = parseRows([data]);
    return row === undefined ? null : toClientWithCounts(row);
  }

  return {
    async create(name): Promise<Result<Client, DomainError>> {
      const { data, error, status } = await supabase.rpc('create_client', { p_name: name });
      if (error) return err(refusalOf('create_client', error, status));

      const row = clientRowSchema.safeParse(data);
      if (!row.success) throw new Error('create_client returned a row that is not understood');
      return ok(toClient(row.data, NEW_CLIENT_COUNTERS));
    },

    find,

    async update(clientId, patch: ClientPatch): Promise<Result<Client, DomainError>> {
      const { error, status } = await supabase.rpc('update_client', {
        p_client_id: clientId,
        ...(patch.name === undefined ? {} : { p_name: patch.name }),
        ...(patch.archived === undefined ? {} : { p_archived: patch.archived }),
      });
      if (error) return err(refusalOf('update_client', error, status));

      // The function returns the row without counters: read the client again for them.
      const updated = await find(clientId);
      if (updated === null)
        throw new Error('update_client succeeded but the client cannot be read');
      return ok(updated);
    },

    async list({ limit, after, includeArchived }): Promise<ClientPage> {
      // One extra row tells whether another page exists.
      const wanted = limit + 1;
      const rows: ClientWithCountsRow[] = [];

      if (after !== undefined) {
        // The order is `created_at` descending and then `id` ascending, so what follows the position
        // is (1) the rows with the SAME `created_at` and a larger `id`, then (2) the older rows.
        // PostgREST has no tuple comparison and `.or()` may not carry a value (spec §3.8), so the
        // two parts are two plain queries, the second one only if the first did not fill the page.
        const sameInstant = await clientsQuery(includeArchived)
          .eq('created_at', after.createdAt)
          .gt('id', after.id)
          .order('id', { ascending: true })
          .limit(wanted);
        if (sameInstant.error) {
          throw upstreamFailure('list the clients', sameInstant.error, sameInstant.status);
        }
        rows.push(...parseRows(sameInstant.data));
      }

      if (rows.length < wanted) {
        let older = clientsQuery(includeArchived)
          .order('created_at', { ascending: false })
          .order('id', { ascending: true })
          .limit(wanted - rows.length);
        if (after !== undefined) older = older.lt('created_at', after.createdAt);
        const result = await older;
        if (result.error) throw upstreamFailure('list the clients', result.error, result.status);
        rows.push(...parseRows(result.data));
      }

      const pageRows = rows.slice(0, limit);
      const last = pageRows.at(-1);
      const next: ClientListPosition | null =
        rows.length > limit && last !== undefined
          ? { createdAt: last.created_at, id: last.id }
          : null;
      return { items: pageRows.map(toClientWithCounts), next };
    },
  };
}
