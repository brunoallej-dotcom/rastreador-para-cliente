import type { SupabaseClient } from '@supabase/supabase-js';
import { z } from 'zod';
import type { Database } from '@/shared/db/database.types';
import { upstreamFailure } from '@/shared/db/upstream-errors';
import {
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
import { ClientArchivedError, ProcessNotActiveError, StaleStageError } from '../domain/errors';
import {
  currentStageOf,
  invariantViolations,
  PROCESS_STATUSES,
  summaryViolations,
  type InvariantViolation,
  type Process,
  type ProcessListPosition,
  type ProcessPage,
  type ProcessPatch,
  type ProcessStatus,
  type ProcessSummary,
} from '../domain/process';
import type { NewProcess, ProcessRepository } from '../domain/process-repository';
import {
  MAX_STAGES_PER_PROCESS,
  STAGE_STATUSES,
  type Stage,
  type StageTemplate,
} from '../domain/stage';
import { getClientStatus } from './supabase-client-directory';
import { timestampSchema } from './timestamp-schema';

/** Postgres: `insufficient_privilege`, what the database functions raise for a denied caller. */
const INSUFFICIENT_PRIVILEGE = '42501';
/** Postgres: `raise_exception`, with the application code as the message (spec §3.7). */
const RAISE_EXCEPTION = 'P0001';
/** SQLSTATE class 22, "data exception": the database refused a value it was given (a bad timestamp...). */
const DATA_EXCEPTION_CLASS = '22';
const NOT_FOUND_MESSAGE = 'NOT_FOUND';
const INVALID_INPUT_MESSAGE = 'INVALID_INPUT';
const CLIENT_ARCHIVED_MESSAGE = 'CLIENT_ARCHIVED';
const PROCESS_NOT_ACTIVE_MESSAGE = 'PROCESS_NOT_ACTIVE';
const STALE_STAGE_MESSAGE = 'STALE_STAGE';
/**
 * Postgres rolled the whole transaction back and nothing of it persisted (no row, no audit event), so
 * repeating the call is safe: `deadlock_detected` and `serialization_failure`. PostgREST answers
 * both with HTTP 500, which `upstreamFailure` would already turn into a 503; the SQLSTATE is matched
 * on its own, whatever the status, so a PostgREST that changes it does not turn a retry into a 500.
 */
const ROLLED_BACK_TRANSIENTLY: ReadonlySet<string> = new Set(['40P01', '40001']);

/** The columns of `processes`, explicit (no `select *`). */
const PROCESS_COLUMNS =
  'id, client_id, title, status, version, created_at, updated_at, completed_at, cancelled_at';

/**
 * The detail read: the process, its client (many to one: one object), its stages with the approval
 * of each (the approval comes as a list of zero or one because the foreign key is composite) and
 * the CEO who gave it. RLS applies to every embedded row; a CEO session sees all of them.
 */
const DETAIL_SELECT =
  `${PROCESS_COLUMNS}, client:clients(id, name), ` +
  'stages:process_stages(id, position, name, description, status, started_at, completed_at, ' +
  'approval:stage_approvals(approved_at, approver:profiles(id, display_name)))';

/**
 * The list read: the process plus what a row of the list shows of its stages, taken with
 * PostgREST's embedded `count` and an embedded list. The same relation is embedded three times
 * under three aliases; two are narrowed by an embedded filter (see the two constants below).
 */
const SUMMARY_SELECT =
  `${PROCESS_COLUMNS}, total_stages:process_stages(count), ` +
  'completed_stages:process_stages(count), current_stage:process_stages(id, position, name)';
/** The embedded filters that narrow `completed_stages` and `current_stage`. */
const COMPLETED_STAGES_STATUS_COLUMN = 'completed_stages.status';
const CURRENT_STAGE_STATUS_COLUMN = 'current_stage.status';

const processRowSchema = z.object({
  id: z.guid(),
  client_id: z.guid(),
  title: z.string(),
  status: z.enum(PROCESS_STATUSES),
  version: z.number().int().min(1),
  created_at: timestampSchema,
  updated_at: timestampSchema,
  completed_at: timestampSchema.nullable(),
  cancelled_at: timestampSchema.nullable(),
});

const approvalRowSchema = z.object({
  approved_at: timestampSchema,
  approver: z.object({ id: z.guid(), display_name: z.string() }),
});

const stageRowSchema = z.object({
  id: z.guid(),
  position: z.number().int().min(1).max(MAX_STAGES_PER_PROCESS),
  name: z.string(),
  description: z.string().nullable(),
  status: z.enum(STAGE_STATUSES),
  started_at: timestampSchema.nullable(),
  completed_at: timestampSchema.nullable(),
  approval: z.array(approvalRowSchema).max(1),
});

/** A process with no stage breaks I1 and the contract (`stages.minItems: 1`): not understood (500). */
const processDetailRowSchema = processRowSchema.extend({
  client: z.object({ id: z.guid(), name: z.string() }),
  stages: z.array(stageRowSchema).min(1).max(MAX_STAGES_PER_PROCESS),
});

/** What an embedded `count` looks like: a list with exactly one `{ count }`. */
const embeddedCountSchema = z.tuple([z.object({ count: z.number().int().nonnegative() })]);

const processSummaryRowSchema = processRowSchema.extend({
  total_stages: z.tuple([z.object({ count: z.number().int().min(1) })]),
  completed_stages: embeddedCountSchema,
  current_stage: z
    .array(
      z.object({
        id: z.guid(),
        position: z.number().int().min(1).max(MAX_STAGES_PER_PROCESS),
        name: z.string(),
      }),
    )
    .max(1),
});

const templateRowsSchema = z
  .array(
    z.object({
      position: z.number().int().min(1).max(MAX_STAGES_PER_PROCESS),
      name: z.string(),
      description: z.string().nullable(),
    }),
  )
  .min(1)
  .max(MAX_STAGES_PER_PROCESS);

type ProcessDetailRow = z.infer<typeof processDetailRowSchema>;
type ProcessSummaryRow = z.infer<typeof processSummaryRowSchema>;

const dateOrNull = (value: string | null): Date | null => (value === null ? null : new Date(value));

function toStage(row: ProcessDetailRow['stages'][number]): Stage {
  const [approval] = row.approval;
  return {
    id: row.id,
    position: row.position,
    name: row.name,
    description: row.description,
    status: row.status,
    startedAt: dateOrNull(row.started_at),
    completedAt: dateOrNull(row.completed_at),
    approval:
      approval === undefined
        ? null
        : {
            approvedBy: { id: approval.approver.id, displayName: approval.approver.display_name },
            approvedAt: new Date(approval.approved_at),
          },
  };
}

function toProcess(row: ProcessDetailRow): Process {
  return {
    id: row.id,
    clientId: row.client_id,
    client: { id: row.client.id, name: row.client.name },
    title: row.title,
    status: row.status,
    version: row.version,
    createdAt: new Date(row.created_at),
    updatedAt: new Date(row.updated_at),
    completedAt: dateOrNull(row.completed_at),
    cancelledAt: dateOrNull(row.cancelled_at),
    stages: row.stages.map(toStage).sort((a, b) => a.position - b.position),
  };
}

function toSummary(row: ProcessSummaryRow): ProcessSummary {
  const [current] = row.current_stage;
  return {
    id: row.id,
    clientId: row.client_id,
    title: row.title,
    status: row.status,
    currentStage:
      current === undefined
        ? null
        : { id: current.id, position: current.position, name: current.name },
    totalStages: row.total_stages[0].count,
    completedStages: row.completed_stages[0].count,
    version: row.version,
    createdAt: new Date(row.created_at),
    updatedAt: new Date(row.updated_at),
    completedAt: dateOrNull(row.completed_at),
    cancelledAt: dateOrNull(row.cancelled_at),
  };
}

/** A row is read from the database as untrusted data: what does not match fails closed (500). */
function parseSummaryRows(data: unknown): ProcessSummaryRow[] {
  const parsed = z.array(processSummaryRowSchema).safeParse(data);
  if (!parsed.success) throw new Error('the processes table returned a row that is not understood');
  return parsed.data;
}

/**
 * What may travel as the `cause` of an error: the SQLSTATE and the HTTP status, never the message or
 * the details of the database error. Those can carry the row ("Failing row contains (..., <title>)")
 * and the logger writes the `cause` chain of every 5xx error, so a title would end up in the logs
 * (SEC-16 keeps titles out of the trail; the logs follow the same rule).
 */
const safeCause = (error: { code?: string }, status: number) => ({
  code: error.code ?? '',
  status,
});

const invalidInput = (code: string | undefined) =>
  new ValidationError(
    'the database refused the input',
    [{ path: 'body', message: 'Invalid input' }],
    { cause: { code: code ?? '' } },
  );

/** The refusal of a list position (the cursor) that the database could not read as a timestamp. */
const invalidPosition = (code: string) =>
  new ValidationError(
    'the database refused the list position',
    [{ path: 'query.cursor', message: 'Invalid cursor' }],
    { cause: { code } },
  );

export type ProcessRepositoryOptions = {
  readonly logger: Pick<Logger, 'warn' | 'error'>;
};

/**
 * `ProcessRepository` over Supabase, as the signed-in user (the request-scoped client, never the
 * admin client): reads go through `from('processes')` and RLS, writes only through the
 * `create_process`, `update_process` and `approve_current_stage` functions, which check the CEO role,
 * `aal2` and the TOTP factor by themselves and write the audit event in the same transaction.
 *
 * Whatever comes back is validated with Zod. Database errors are mapped by the table of spec §3.7;
 * an unmapped one is an unexpected error (500) and a slow or dead database is a 503 (E-21). The
 * functions return the process row only, so after a write the process is read again, with its
 * stages, approvals and client; the write is already committed by then, and a process that cannot be
 * read now (the row is gone, or the session ended between the two calls) is answered as not found.
 */
export function createSupabaseProcessRepository(
  supabase: SupabaseClient<Database>,
  options: ProcessRepositoryOptions,
): ProcessRepository {
  /** The list query: the processes of a client, with their progress, optionally in one status. */
  const summariesQuery = (clientId: string, status: ProcessStatus | undefined) => {
    const query = supabase
      .from('processes')
      .select(SUMMARY_SELECT)
      .eq('client_id', clientId)
      .eq(COMPLETED_STAGES_STATUS_COLUMN, 'completed')
      .eq(CURRENT_STAGE_STATUS_COLUMN, 'in_progress')
      // postgrest-js retries a GET with backoff on its own (about 7 s on a dead upstream): without
      // this the 5 s bound of E-21 would not hold.
      .retry(false);
    return status === undefined ? query : query.eq('status', status);
  };

  /** Maps what a write function raised. Returns the domain error, or throws for the unexpected. */
  function refusalOf(
    operation: 'create_process' | 'update_process' | 'approve_current_stage',
    notFoundDetail: string,
    error: { code?: string; message: string },
    status: number,
  ): DomainError {
    if (error.code === INSUFFICIENT_PRIVILEGE) {
      // Layer 1 should have stopped this caller: a denial here means it was bypassed (spec §3.7).
      options.logger.warn({ event: 'authz.database_denied', operation }, 'authz.database_denied');
      return new ForbiddenError(`${operation} denied the caller`, { detail: 'Access denied.' });
    }
    if (error.code === RAISE_EXCEPTION && error.message === NOT_FOUND_MESSAGE) {
      return new NotFoundError(`${operation} found no such resource`, { detail: notFoundDetail });
    }
    if (error.code === RAISE_EXCEPTION && error.message === CLIENT_ARCHIVED_MESSAGE) {
      return new ClientArchivedError({ cause: { code: error.code } });
    }
    if (error.code === RAISE_EXCEPTION && error.message === PROCESS_NOT_ACTIVE_MESSAGE) {
      return new ProcessNotActiveError({ cause: { code: error.code } });
    }
    // Only `INVALID_INPUT` is the caller's fault. A check violation (23514) or a value that is too long
    // (22001) cannot come from the input of these two functions: `private.visible_text` is stricter
    // than every CHECK of the tables they write, so one of those is a defect (a template row, a CHECK
    // that drifted) and answers 500, never a 400 that blames the CEO (F-86). It falls to the
    // unexpected-error branch below, with only the SQLSTATE and the status as cause.
    if (error.code === RAISE_EXCEPTION && error.message === INVALID_INPUT_MESSAGE) {
      return invalidInput(error.code);
    }
    if (error.code !== undefined && ROLLED_BACK_TRANSIENTLY.has(error.code)) {
      // 503 with Retry-After, like any transient failure: nothing was written.
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
    after: ProcessListPosition | undefined,
  ): Error {
    if (after !== undefined && error.code?.startsWith(DATA_EXCEPTION_CLASS) === true) {
      return invalidPosition(error.code);
    }
    return upstreamFailure('list the processes', safeCause(error, status), status);
  }

  /**
   * A process that does not hold its invariants (I1 to I5) is corrupt data, and the panel must not
   * show it: the read fails closed (500). The error log names the process and the invariants that
   * broke, and nothing else (no title, no stage name: SEC-16 keeps them out of the logs too). The two
   * functions are the only writers, so this only fires for a row made by hand (a fixture, an operator
   * with the secret key) or a defect; one such process fails the whole list of its client, which is the
   * price of never showing a broken one (spec §3.7.2, F-81).
   */
  function failOnViolations(processId: string, violations: readonly InvariantViolation[]): void {
    if (violations.length === 0) return;
    const invariants = [...new Set(violations.map((violation) => violation.invariant))].sort();
    options.logger.error(
      { event: 'tracking.process_invariant_violated', processId, invariants },
      'tracking.process_invariant_violated',
    );
    throw new Error('a process read from the database breaks its invariants');
  }

  async function find(processId: string): Promise<Process | null> {
    const { data, error, status } = await supabase
      .from('processes')
      .select(DETAIL_SELECT)
      .eq('id', processId)
      .order('position', { referencedTable: 'stages', ascending: true })
      .retry(false)
      .maybeSingle();
    if (error) throw upstreamFailure('read the process', safeCause(error, status), status);
    if (data === null) return null;

    const row = processDetailRowSchema.safeParse(data);
    if (!row.success) throw new Error('the processes table returned a row that is not understood');
    const process = toProcess(row.data);
    failOnViolations(process.id, invariantViolations(process));
    return process;
  }

  /** The process a write just committed, read again: gone means 404, as for any vanished row. */
  async function readAfterWrite(processId: string): Promise<Result<Process, DomainError>> {
    const process = await find(processId);
    if (process === null) {
      return err(
        new NotFoundError('process not found after write', { detail: 'Process not found.' }),
      );
    }
    return ok(process);
  }

  /**
   * The conflict of an approval whose expected stage is not the current one: the stage that is current
   * NOW, read again, because the function's error carries nothing of the row (spec §3.7.3). Only an
   * active process has a current stage to name; one that is no longer active (a cancellation or the last
   * approval landed in between) has none (`null`, the contract's `StaleStageProblem`). A process that
   * cannot be read any more is a 404, like any row that vanished after a write.
   */
  async function staleStageOf(processId: string): Promise<DomainError> {
    const process = await find(processId);
    if (process === null) {
      return new NotFoundError('process not found after a stale approval', {
        detail: 'Process not found.',
      });
    }
    const current = process.status === 'active' ? currentStageOf(process) : null;
    return new StaleStageError(current?.id ?? null, { cause: { code: RAISE_EXCEPTION } });
  }

  return {
    async create(input: NewProcess): Promise<Result<Process, DomainError>> {
      const { data, error, status } = await supabase.rpc('create_process', {
        p_client_id: input.clientId,
        p_title: input.title,
        ...(input.stages === null
          ? {}
          : {
              p_stages: input.stages.map((stage) => ({
                name: stage.name,
                description: stage.description,
              })),
            }),
      });
      if (error) return err(refusalOf('create_process', 'Client not found.', error, status));

      const row = processRowSchema.safeParse(data);
      if (!row.success) throw new Error('create_process returned a row that is not understood');
      return readAfterWrite(row.data.id);
    },

    find,

    async update(processId, patch: ProcessPatch): Promise<Result<Process, DomainError>> {
      const { error, status } = await supabase.rpc('update_process', {
        p_process_id: processId,
        ...(patch.title === undefined ? {} : { p_title: patch.title }),
        ...(patch.cancel === undefined ? {} : { p_cancel: patch.cancel }),
      });
      if (error) return err(refusalOf('update_process', 'Process not found.', error, status));

      return readAfterWrite(processId);
    },

    async approve(processId, expectedStageId): Promise<Result<Process, DomainError>> {
      const { error, status } = await supabase.rpc('approve_current_stage', {
        p_process_id: processId,
        p_expected_stage_id: expectedStageId,
      });
      if (error) {
        if (error.code === RAISE_EXCEPTION && error.message === STALE_STAGE_MESSAGE) {
          return err(await staleStageOf(processId));
        }
        return err(refusalOf('approve_current_stage', 'Process not found.', error, status));
      }

      return readAfterWrite(processId);
    },

    async listByClient(clientId, { limit, after, status }): Promise<ProcessPage | null> {
      // One extra row tells whether another page exists.
      const wanted = limit + 1;
      const rows: ProcessSummaryRow[] = [];

      if (after !== undefined) {
        // The order is `created_at` descending and then `id` ascending, so what follows the position
        // is (1) the rows with the SAME `created_at` and a larger `id`, then (2) the older rows.
        // PostgREST has no tuple comparison and `.or()` may not carry a value (spec §3.8), so the
        // two parts are two plain queries, the second one only if the first did not fill the page.
        const sameInstant = await summariesQuery(clientId, status)
          .eq('created_at', after.createdAt)
          .gt('id', after.id)
          .order('id', { ascending: true })
          .limit(wanted);
        if (sameInstant.error) throw listFailure(sameInstant.error, sameInstant.status, after);
        rows.push(...parseSummaryRows(sameInstant.data));
      }

      if (rows.length < wanted) {
        let older = summariesQuery(clientId, status)
          .order('created_at', { ascending: false })
          .order('id', { ascending: true })
          .limit(wanted - rows.length);
        if (after !== undefined) older = older.lt('created_at', after.createdAt);
        const result = await older;
        if (result.error) throw listFailure(result.error, result.status, after);
        rows.push(...parseSummaryRows(result.data));
      }

      // No row at all: a client with no process (an empty page) or a client that is not there (404).
      // A row proves the client exists, so the check only runs for an empty answer.
      if (rows.length === 0 && (await getClientStatus(supabase, clientId)) === null) return null;

      const pageRows = rows.slice(0, limit);
      const last = pageRows.at(-1);
      const next: ProcessListPosition | null =
        rows.length > limit && last !== undefined
          ? { createdAt: last.created_at, id: last.id }
          : null;
      const items = pageRows.map(toSummary);
      for (const item of items) failOnViolations(item.id, summaryViolations(item));
      return { items, next };
    },

    async defaultStageTemplate(): Promise<StageTemplate> {
      const { data, error, status } = await supabase
        .from('default_stage_template')
        .select('position, name, description')
        .order('position', { ascending: true })
        .retry(false);
      if (error) throw upstreamFailure('read the stage template', safeCause(error, status), status);

      const rows = templateRowsSchema.safeParse(data);
      if (!rows.success) throw new Error('the stage template is not understood');
      return { stages: rows.data };
    },
  };
}
