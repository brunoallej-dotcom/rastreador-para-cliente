import type { SupabaseClient } from '@supabase/supabase-js';
import { z } from 'zod';
import type { Database } from '@/shared/db/database.types';
import { upstreamFailure } from '@/shared/db/upstream-errors';
import {
  ConflictError,
  err,
  ForbiddenError,
  NotFoundError,
  ok,
  ServiceUnavailableError,
  ValidationError,
  type DomainError,
  type Result,
} from '@/shared/kernel';
import type { Logger } from '@/shared/observability/logger';
import type { Client, ClientListPosition, ClientPage, ClientPatch } from '../domain/client';
import type { ClientRepository } from '../domain/client-repository';
import { timestampSchema } from './timestamp-schema';

/** Postgres: `insufficient_privilege`, what the database functions raise for a denied caller. */
const INSUFFICIENT_PRIVILEGE = '42501';
/** Postgres: `raise_exception`, with the application code as the message (spec §3.7). */
const RAISE_EXCEPTION = 'P0001';
const CHECK_VIOLATION = '23514';
const STRING_DATA_RIGHT_TRUNCATION = '22001';
/** SQLSTATE class 22, "data exception": the database refused a value it was given (a bad timestamp...). */
const DATA_EXCEPTION_CLASS = '22';
const NOT_FOUND_MESSAGE = 'NOT_FOUND';
const INVALID_INPUT_MESSAGE = 'INVALID_INPUT';
/**
 * What `create_client` and `update_client` raise (`P0001`) when the name is already an active
 * client's: the database turns the violation of its unique index into this business error (spec
 * §3.7.1, F-51), so a raw `23505` is never expected here.
 */
const NAME_TAKEN_MESSAGE = 'CLIENT_NAME_TAKEN';
/**
 * Postgres rolled the whole transaction back and nothing of it persisted (no row, no audit event), so
 * repeating the call is safe: `deadlock_detected` (two renames that cross wait on each other's
 * name, F-51) and `serialization_failure`. PostgREST answers both with HTTP 500 (probed on the local
 * stack; 23505 gets 409), which `upstreamFailure` would already turn into a 503; the SQLSTATE is
 * matched on its own, whatever the status, so a PostgREST that changes it does not turn a retry
 * into a 500.
 */
const ROLLED_BACK_TRANSIENTLY: ReadonlySet<string> = new Set(['40P01', '40001']);

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

/** A client as the database function returns it: no counters (a new client has none). */
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

/**
 * What may travel as the `cause` of an error: the SQLSTATE and the HTTP status, never the message or
 * the details of the database error. Those can carry the row ("Failing row contains (..., <name>)")
 * and the logger writes the `cause` chain of every 5xx error, so a client name would end up in the
 * logs (SEC-16 keeps names out of the trail; the logs follow the same rule).
 */
const safeCause = (error: { code?: string }, status: number) => ({
  code: error.code ?? '',
  status,
});

const invalidInput = (code: string | undefined) =>
  new ValidationError(
    'the database refused the input',
    [{ path: 'body', message: 'Invalid input' }],
    {
      cause: { code: code ?? '' },
    },
  );

/** The refusal of a list position (the cursor) that the database could not read as a timestamp. */
const invalidPosition = (code: string) =>
  new ValidationError(
    'the database refused the list position',
    [{ path: 'query.cursor', message: 'Invalid cursor' }],
    { cause: { code } },
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
 * Whatever comes back is validated with Zod. Database errors are mapped by the table of spec §3.7
 * (a name already taken by an active client, `CLIENT_NAME_TAKEN`, is a `ConflictError`: 409, F-51);
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
    if (error.code === RAISE_EXCEPTION && error.message === NAME_TAKEN_MESSAGE) {
      // 409 CONFLICT. The detail names no client (not its id, not its name): the database error did
      // not carry them and the answer must not either.
      return new ConflictError(`${operation}: the name is already an active client's`, {
        detail: 'A client with this name already exists.',
        cause: { code: error.code },
      });
    }
    if (
      (error.code === RAISE_EXCEPTION && error.message === INVALID_INPUT_MESSAGE) ||
      error.code === CHECK_VIOLATION ||
      error.code === STRING_DATA_RIGHT_TRUNCATION
    ) {
      return invalidInput(error.code);
    }
    if (error.code !== undefined && ROLLED_BACK_TRANSIENTLY.has(error.code)) {
      // 503 with Retry-After, like any transient failure: the caller repeats and gets the 409 or
      // the 200 the first call would have had.
      throw new ServiceUnavailableError(`${operation}: the transaction was rolled back`, {
        cause: safeCause(error, status),
      });
    }
    throw upstreamFailure(operation, safeCause(error, status), status);
  }

  /**
   * What a failed list query becomes. A position the database cannot read (class 22: a timestamp out
   * of range, an offset it refuses) is the caller's cursor, so it is a 400 on `query.cursor`; the
   * cursor schema already bounds what it accepts, this is the backstop for what slips through.
   * Anything else is unexpected (500) or an outage (503).
   */
  function listFailure(
    error: { code?: string },
    status: number,
    after: ClientListPosition | undefined,
  ): Error {
    if (after !== undefined && error.code?.startsWith(DATA_EXCEPTION_CLASS) === true) {
      return invalidPosition(error.code);
    }
    return upstreamFailure('list the clients', safeCause(error, status), status);
  }

  async function find(clientId: string): Promise<Client | null> {
    const { data, error, status } = await supabase
      .from('clients')
      .select(CLIENT_SELECT)
      .eq('id', clientId)
      .eq(ACTIVE_PROCESSES_STATUS_COLUMN, 'active')
      .retry(false)
      .maybeSingle();
    if (error) throw upstreamFailure('read the client', safeCause(error, status), status);
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

      // The function returns the row without the counters, and PostgREST cannot narrow an embed on a
      // function result to the active processes, so the client is read again. The write is already
      // committed (an identical PATCH is a no-op, so a retry is safe); a client that cannot be read
      // now, because the row is gone or the session ended between the two calls, is answered as not
      // found.
      const updated = await find(clientId);
      if (updated === null) {
        return err(
          new NotFoundError('client not found after update', { detail: 'Client not found.' }),
        );
      }
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
        if (sameInstant.error) throw listFailure(sameInstant.error, sameInstant.status, after);
        rows.push(...parseRows(sameInstant.data));
      }

      if (rows.length < wanted) {
        let older = clientsQuery(includeArchived)
          .order('created_at', { ascending: false })
          .order('id', { ascending: true })
          .limit(wanted - rows.length);
        if (after !== undefined) older = older.lt('created_at', after.createdAt);
        const result = await older;
        if (result.error) throw listFailure(result.error, result.status, after);
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
