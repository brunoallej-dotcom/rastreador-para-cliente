import type { SupabaseClient } from '@supabase/supabase-js';
import { z } from 'zod';
import type { Database } from '@/shared/db/database.types';
import { upstreamFailure } from '@/shared/db/upstream-errors';
import { ServiceUnavailableError, ValidationError } from '@/shared/kernel';
import type { Logger } from '@/shared/observability/logger';
import {
  stageOrderViolations,
  type ClientProcessQueries,
  type MyProcessDetail,
  type MyProcessPage,
  type MyProcessSummary,
  type MyStage,
} from '../domain/client-process-queries';
import {
  PROCESS_STATUSES,
  summaryViolations,
  type InvariantViolation,
  type ProcessListPosition,
  type SummaryCounters,
} from '../domain/process';
import { MAX_STAGES_PER_PROCESS, STAGE_STATUSES } from '../domain/stage';
import { timestampSchema } from './timestamp-schema';

/** SQLSTATE class 22, "data exception": the database refused a value it was given (a bad timestamp...). */
const DATA_EXCEPTION_CLASS = '22';
/**
 * Postgres rolled the statement back and nothing of it persisted: `deadlock_detected` and
 * `serialization_failure`. For a read it means "try again", which is a 503 with `Retry-After`, never a
 * 500 that blames the code. The SQLSTATE is matched on its own, whatever the HTTP status PostgREST
 * chose for it, as the writes of `supabase-process-repository.ts` do.
 */
const ROLLED_BACK_TRANSIENTLY: ReadonlySet<string> = new Set(['40P01', '40001']);

/**
 * The columns of `processes` the panel reads, explicit (no `select *`): no `version` (the contract has
 * none for a client). `client_id` is read only to be compared with the tenant (see `assertTenant`) and
 * `cancelled_at` only for the invariants; neither is ever mapped to the response.
 */
const PROCESS_COLUMNS =
  'id, client_id, title, status, created_at, updated_at, completed_at, cancelled_at';

/**
 * The detail read: the process and its stages. NOT the approvals: a client cannot read
 * `stage_approvals` (RLS, spec §4.2) and the panel has no use for who gave the "Ok". RLS applies to
 * the embedded stages too.
 */
const DETAIL_SELECT =
  `${PROCESS_COLUMNS}, ` +
  'stages:process_stages(position, name, description, status, started_at, completed_at)';

/**
 * The list read: the process plus what a row of the list shows of its stages, taken with PostgREST's
 * embedded `count` and an embedded list. The same relation is embedded three times under three
 * aliases; two are narrowed by an embedded filter (see the two constants below).
 */
const SUMMARY_SELECT =
  `${PROCESS_COLUMNS}, total_stages:process_stages(count), ` +
  'completed_stages:process_stages(count), current_stage:process_stages(position, name)';
/** The embedded filters that narrow `completed_stages` and `current_stage`. */
const COMPLETED_STAGES_STATUS_COLUMN = 'completed_stages.status';
const CURRENT_STAGE_STATUS_COLUMN = 'current_stage.status';

const processRowSchema = z.object({
  id: z.guid(),
  client_id: z.guid(),
  title: z.string(),
  status: z.enum(PROCESS_STATUSES),
  created_at: timestampSchema,
  updated_at: timestampSchema,
  completed_at: timestampSchema.nullable(),
  cancelled_at: timestampSchema.nullable(),
});

/**
 * The two members the tenant check needs, and nothing else. It runs on the raw rows BEFORE the full
 * schemas, so a row of another tenant that is also malformed still raises the tenant alarm instead of
 * "not understood" (F-98): the more serious signal wins.
 */
const tenantIdentitySchema = z.object({ id: z.guid(), client_id: z.guid() });

const stagePositionSchema = z.number().int().min(1).max(MAX_STAGES_PER_PROCESS);

const stageRowSchema = z.object({
  position: stagePositionSchema,
  name: z.string(),
  description: z.string().nullable(),
  status: z.enum(STAGE_STATUSES),
  started_at: timestampSchema.nullable(),
  completed_at: timestampSchema.nullable(),
});

/** A process with no stage breaks I1 and the contract (`stages.minItems: 1`): not understood (500). */
const detailRowSchema = processRowSchema.extend({
  stages: z.array(stageRowSchema).min(1).max(MAX_STAGES_PER_PROCESS),
});

/** What an embedded `count` looks like: a list with exactly one `{ count }`. */
const embeddedCountSchema = z.tuple([z.object({ count: z.number().int().nonnegative() })]);

const summaryRowSchema = processRowSchema.extend({
  total_stages: z.tuple([z.object({ count: z.number().int().min(1) })]),
  completed_stages: embeddedCountSchema,
  current_stage: z.array(z.object({ position: stagePositionSchema, name: z.string() })).max(1),
});

type DetailRow = z.infer<typeof detailRowSchema>;
type SummaryRow = z.infer<typeof summaryRowSchema>;

const dateOrNull = (value: string | null): Date | null => (value === null ? null : new Date(value));

/** What `summaryViolations` reads of a row of the list. */
function countersOfSummary(row: SummaryRow): SummaryCounters {
  const [current] = row.current_stage;
  return {
    status: row.status,
    totalStages: row.total_stages[0].count,
    completedStages: row.completed_stages[0].count,
    currentStage: current === undefined ? null : { position: current.position },
    completedAt: dateOrNull(row.completed_at),
    cancelledAt: dateOrNull(row.cancelled_at),
  };
}

function toSummary(row: SummaryRow): MyProcessSummary {
  const [current] = row.current_stage;
  return {
    id: row.id,
    title: row.title,
    status: row.status,
    currentStage: current === undefined ? null : { position: current.position, name: current.name },
    totalStages: row.total_stages[0].count,
    completedStages: row.completed_stages[0].count,
    createdAt: new Date(row.created_at),
    updatedAt: new Date(row.updated_at),
    completedAt: dateOrNull(row.completed_at),
  };
}

const toStage = (row: DetailRow['stages'][number]): MyStage => ({
  position: row.position,
  name: row.name,
  description: row.description,
  status: row.status,
  startedAt: dateOrNull(row.started_at),
  completedAt: dateOrNull(row.completed_at),
});

function toDetail(row: DetailRow): MyProcessDetail {
  const stages = row.stages.map(toStage).sort((a, b) => a.position - b.position);
  const current = stages.find((stage) => stage.status === 'in_progress');
  return {
    id: row.id,
    title: row.title,
    status: row.status,
    currentStage: current === undefined ? null : { position: current.position, name: current.name },
    totalStages: stages.length,
    completedStages: stages.filter((stage) => stage.status === 'completed').length,
    createdAt: new Date(row.created_at),
    updatedAt: new Date(row.updated_at),
    completedAt: dateOrNull(row.completed_at),
    stages,
  };
}

/** What `detailRowSchema` and `summaryRowSchema` refuse is data the panel does not understand: 500. */
const notUnderstood = () => new Error('the processes table returned a row that is not understood');

/**
 * What may travel as the `cause` of an error: the SQLSTATE and the HTTP status, never the message, the
 * details or the hint of the database error. Those can carry the row ("Failing row contains (...,
 * <title>)") and the logger writes the `cause` chain of every 5xx error, so a title would end up in the
 * logs (SEC-16). The same shape as `supabase-process-repository.ts`.
 */
const safeCause = (error: { code?: string }, status: number) => ({
  code: error.code ?? '',
  status,
});

/** The refusal of a list position (the cursor) that the database could not read as a timestamp. */
const invalidPosition = (code: string) =>
  new ValidationError(
    'the database refused the list position',
    [{ path: 'query.cursor', message: 'Invalid cursor' }],
    { cause: { code } },
  );

export type ClientProcessQueriesOptions = {
  readonly logger: Pick<Logger, 'error' | 'warn'>;
};

/**
 * `ClientProcessQueries` over Supabase, as the signed-in CLIENT (the request-scoped client, never the
 * admin client). It is a query service of its own, apart from `ProcessRepository` (spec §3.2): it
 * reads only `processes` and `process_stages`, the two tables a client may read, and only the columns
 * of the contract's `MyProcess*` schemas.
 *
 * The tenant is enforced three times: the query filters by the `clientId` of the session (the index
 * `processes (client_id, created_at DESC, id)` serves it), RLS filters by the profile of the session
 * (`private.current_client_id()`), and every row that comes back is compared with the tenant before
 * anything is mapped (`assertTenant`). The first two are independent: a row of another client needs
 * BOTH to fail. The third is what turns that double failure (a bug in the filter AND a policy dropped
 * or loosened by a bad migration) into a 500 that shows nothing, instead of a leak. It is a tripwire for
 * the two failing together, not a test of RLS: an RLS regression ALONE is invisible here, because the
 * filter still holds, and is caught by pgTAP (003 and 018, which also inventory the policies of the three
 * tables, F-97).
 *
 * Whatever comes back is validated with Zod, and a process that does not hold its invariants (no
 * stage, progress that does not add up) fails closed (500), as in the CEO panel (F-81).
 */
export function createSupabaseClientProcessQueries(
  supabase: SupabaseClient<Database>,
  options: ClientProcessQueriesOptions,
): ClientProcessQueries {
  /** The list query: the processes of the tenant, with their progress. */
  const summariesQuery = (clientId: string) =>
    supabase
      .from('processes')
      .select(SUMMARY_SELECT)
      .eq('client_id', clientId)
      .eq(COMPLETED_STAGES_STATUS_COLUMN, 'completed')
      .eq(CURRENT_STAGE_STATUS_COLUMN, 'in_progress')
      // postgrest-js retries a GET with backoff on its own (about 7 s on a dead upstream): without
      // this the 5 s bound of E-21 would not hold.
      .retry(false);

  /**
   * What a failed read becomes: a transaction Postgres rolled back is 503 (nothing was lost, trying again
   * is safe), a slow or dead database is 503 (E-21), anything else is unexpected (500).
   */
  function readFailure(operation: string, error: { code?: string }, status: number): Error {
    if (error.code !== undefined && ROLLED_BACK_TRANSIENTLY.has(error.code)) {
      return new ServiceUnavailableError(`${operation}: the read was rolled back`, {
        cause: safeCause(error, status),
      });
    }
    return upstreamFailure(operation, safeCause(error, status), status);
  }

  /**
   * What a failed list query becomes. A position the database cannot read (class 22: a timestamp out
   * of range, an offset it refuses) is the caller's cursor, so it is a 400 on `query.cursor`; the
   * cursor schema already bounds what it accepts, this is the backstop for what slips through, and a
   * warning says it did (F-98: the bounds of the schema and of the database drifted apart). Anything else
   * is `readFailure`.
   */
  function listFailure(
    error: { code?: string },
    status: number,
    after: ProcessListPosition | undefined,
  ): Error {
    if (after !== undefined && error.code?.startsWith(DATA_EXCEPTION_CLASS) === true) {
      options.logger.warn(
        { event: 'tracking.client_panel_cursor_refused', code: error.code },
        'tracking.client_panel_cursor_refused',
      );
      return invalidPosition(error.code);
    }
    return readFailure('list the client processes', error, status);
  }

  /**
   * A row that is not the tenant's is a defect (the filter and RLS both failed): fail closed, name the
   * process and nothing else (no title, no client id), and map none of the rows. It reads the RAW rows with
   * the two-member schema above, so it runs before, and whatever else is wrong with a foreign row.
   */
  function assertTenant(clientId: string, rawRows: unknown): void {
    const identities = z.array(tenantIdentitySchema).safeParse(rawRows);
    if (!identities.success) throw notUnderstood();
    const foreign = identities.data.find((row) => row.client_id !== clientId);
    if (foreign === undefined) return;
    options.logger.error(
      { event: 'tracking.client_panel_tenant_mismatch', processId: foreign.id },
      'tracking.client_panel_tenant_mismatch',
    );
    throw new Error('the client panel read a process that is not the tenant of the session');
  }

  /**
   * A process that does not hold its invariants is corrupt data, and the panel must not show it: the
   * read fails closed (500). The error log names the process and the invariants that broke, and
   * nothing else (no title, no stage name: SEC-16).
   */
  function failOnViolations(processId: string, violations: readonly InvariantViolation[]): void {
    if (violations.length === 0) return;
    const invariants = [...new Set(violations.map((violation) => violation.invariant))].sort();
    options.logger.error(
      { event: 'tracking.process_invariant_violated', panel: 'client', processId, invariants },
      'tracking.process_invariant_violated',
    );
    throw new Error('a process read from the database breaks its invariants');
  }

  /** The tenant first, then the shape: see `assertTenant`. */
  function parseSummaryRows(clientId: string, data: unknown): SummaryRow[] {
    assertTenant(clientId, data);
    const parsed = z.array(summaryRowSchema).safeParse(data);
    if (!parsed.success) throw notUnderstood();
    return parsed.data;
  }

  return {
    async list(clientId, { limit, after }): Promise<MyProcessPage> {
      // One extra row tells whether another page exists.
      const wanted = limit + 1;
      const rows: SummaryRow[] = [];

      if (after !== undefined) {
        // The order is `created_at` descending and then `id` ascending, so what follows the position
        // is (1) the rows with the SAME `created_at` and a larger `id`, then (2) the older rows.
        // PostgREST has no tuple comparison and `.or()` may not carry a value (spec §3.8), so the
        // two parts are two plain queries, the second one only if the first did not fill the page.
        const sameInstant = await summariesQuery(clientId)
          .eq('created_at', after.createdAt)
          .gt('id', after.id)
          .order('id', { ascending: true })
          .limit(wanted);
        if (sameInstant.error) throw listFailure(sameInstant.error, sameInstant.status, after);
        rows.push(...parseSummaryRows(clientId, sameInstant.data));
      }

      if (rows.length < wanted) {
        let older = summariesQuery(clientId)
          .order('created_at', { ascending: false })
          .order('id', { ascending: true })
          .limit(wanted - rows.length);
        if (after !== undefined) older = older.lt('created_at', after.createdAt);
        const result = await older;
        if (result.error) throw listFailure(result.error, result.status, after);
        rows.push(...parseSummaryRows(clientId, result.data));
      }

      // The invariants are checked on EVERY row that was fetched, the lookahead row included (it is the
      // first row of the next page), so one rule holds for all of them: a corrupt process fails the page
      // that contains it and the page before it, which is the one that would have pointed at it
      // (fail closed: the panel never shows a page that was read next to a defect).
      for (const row of rows) failOnViolations(row.id, summaryViolations(countersOfSummary(row)));
      const pageRows = rows.slice(0, limit);
      const last = pageRows.at(-1);
      const next: ProcessListPosition | null =
        rows.length > limit && last !== undefined
          ? { createdAt: last.created_at, id: last.id }
          : null;
      return { items: pageRows.map(toSummary), next };
    },

    async find(clientId, processId): Promise<MyProcessDetail | null> {
      const { data, error, status } = await supabase
        .from('processes')
        .select(DETAIL_SELECT)
        .eq('id', processId)
        .eq('client_id', clientId)
        .order('position', { referencedTable: 'stages', ascending: true })
        .retry(false)
        .maybeSingle();
      if (error) throw readFailure('read the client process', error, status);
      if (data === null) return null;

      assertTenant(clientId, [data]);
      const parsed = detailRowSchema.safeParse(data);
      if (!parsed.success) throw notUnderstood();

      const detail = toDetail(parsed.data);
      failOnViolations(detail.id, [
        ...stageOrderViolations(detail.stages),
        ...summaryViolations({
          status: detail.status,
          totalStages: detail.totalStages,
          completedStages: detail.completedStages,
          currentStage: detail.currentStage,
          completedAt: detail.completedAt,
          cancelledAt: dateOrNull(parsed.data.cancelled_at),
        }),
      ]);
      return detail;
    },
  };
}
