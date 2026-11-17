import type { SupabaseClient } from '@supabase/supabase-js';
import { z } from 'zod';
import type { Database } from '@/shared/db/database.types';
import { upstreamFailure } from '@/shared/db/upstream-errors';
import { ValidationError } from '@/shared/kernel';
import {
  PROCESS_EVENT_ACTIONS,
  type ProcessEvent,
  type ProcessEventActor,
  type ProcessEventDetails,
  type ProcessEventPage,
  type ProcessEventPosition,
  type ProcessEventQuery,
} from '../domain/process-event';
import type { ProcessEventQueries } from '../domain/process-event-queries';
import { MAX_STAGES_PER_PROCESS, STAGE_NAME_MAX_LENGTH } from '../domain/stage';
import { timestampSchema } from './timestamp-schema';

/** SQLSTATE class 22, "data exception": the database refused a value it was given (an id out of range...). */
const DATA_EXCEPTION_CLASS = '22';
/** The audit action that names a stage as its resource (every other timeline action names the process). */
const STAGE_APPROVED: (typeof PROCESS_EVENT_ACTIONS)[number] = 'stage.approved';

/** The columns of `audit_events` the timeline reads, explicit (no `select *`). */
const EVENT_COLUMNS = 'id, occurred_at, actor_id, action, resource_id';

/**
 * `audit_events.id` is a `bigint`: PostgREST sends it as a JSON number (or, if its configuration ever
 * changes, as digits). Kept as decimal text, which is what the contract's `ProcessEvent.id` is.
 */
const eventIdSchema = z.union([
  z.number().int().positive().refine(Number.isSafeInteger),
  z.string().regex(/^[0-9]{1,19}$/),
]);

const eventRowSchema = z.object({
  id: eventIdSchema,
  occurred_at: timestampSchema,
  actor_id: z.guid().nullable(),
  action: z.enum(PROCESS_EVENT_ACTIONS),
  resource_id: z.guid(),
});
const eventRowsSchema = z.array(eventRowSchema);

/**
 * `process_stages.name` is 1 to 120 characters (the CHECK of the table, `char_length`), and the contract's
 * `stageName` has `maxLength: 120`: both count characters (code points), not UTF-16 units, so the bound
 * is checked on the code points, or a name of 120 emoji would be refused for being 240 units long.
 */
const stageNameSchema = z
  .string()
  .refine((name) => name.length >= 1 && [...name].length <= STAGE_NAME_MAX_LENGTH);

const stageRowsSchema = z.array(
  z.object({
    id: z.guid(),
    position: z.number().int().min(1).max(MAX_STAGES_PER_PROCESS),
    name: stageNameSchema,
  }),
);

const profileRowsSchema = z.array(z.object({ id: z.guid(), display_name: z.string() }));

type EventRow = z.infer<typeof eventRowSchema>;

/**
 * What may travel as the `cause` of an error: the SQLSTATE and the HTTP status, never the message or
 * the details of the database error (the logger writes the `cause` chain of every 5xx error).
 */
const safeCause = (error: { code?: string }, status: number) => ({
  code: error.code ?? '',
  status,
});

/** The refusal of a list position (the cursor) that the database could not read as an id. */
const invalidPosition = (code: string) =>
  new ValidationError(
    'the database refused the list position',
    [{ path: 'query.cursor', message: 'Invalid cursor' }],
    { cause: { code } },
  );

/** A row is read from the database as untrusted data: what does not match fails closed (500). */
function parseRows<T>(schema: z.ZodType<T>, data: unknown, what: string): T {
  const parsed = schema.safeParse(data);
  if (!parsed.success) throw new Error(`${what} returned a row that is not understood`);
  return parsed.data;
}

/**
 * What an event says about a stage: only `stage.approved` names one (its resource). The audit event
 * gives the stage id and the stage row, which no operation renames, gives its position and name. A
 * stage that cannot be found keeps the id alone, which the contract allows (every detail is optional).
 */
function detailsOf(
  row: EventRow,
  stageById: ReadonlyMap<string, { id: string; position: number; name: string }>,
): ProcessEventDetails {
  if (row.action !== STAGE_APPROVED) return {};
  const stage = stageById.get(row.resource_id);
  if (stage === undefined) return { stageId: row.resource_id };
  return { stageId: stage.id, stagePosition: stage.position, stageName: stage.name };
}

/**
 * `ProcessEventQueries` over Supabase, as the signed-in user (the request-scoped client, never the
 * admin client): RLS lets only an attested CEO read `audit_events`, and a CEO reads every stage and
 * profile. Four plain reads, none of them with a value in a PostgREST filter string:
 * 1. the process (a missing one is `null`, a 404);
 * 2. one page of its events, `ORDER BY id`, keyset on the id (one query: the id is unique, so there
 *    is no tie to break) and filtered to the actions the timeline shows;
 * 3. the stages the page's `stage.approved` events name, for their position and name;
 * 4. the profiles of the page's actors, for their display names.
 * 3 and 4 run together and only when the page has something to look up. The audit trail has no foreign
 * key to the stages or the profiles (the history outlives them), so they are joined here.
 *
 * What the timeline says about a stage comes from the stage row, which no operation renames. It says
 * nothing about a title: the audit metadata has none (SEC-16, spec §3.7.2).
 */
export function createSupabaseProcessEventQueries(
  supabase: SupabaseClient<Database>,
): ProcessEventQueries {
  async function processExists(processId: string): Promise<boolean> {
    const { data, error, status } = await supabase
      .from('processes')
      .select('id')
      .eq('id', processId)
      // postgrest-js retries a GET with backoff on its own (about 7 s on a dead upstream): without
      // this the 5 s bound of E-21 would not hold.
      .retry(false)
      .maybeSingle();
    if (error) throw upstreamFailure('read the process', safeCause(error, status), status);
    return data !== null;
  }

  async function readEventRows(
    processId: string,
    limit: number,
    after: ProcessEventPosition | undefined,
  ): Promise<EventRow[]> {
    const base = supabase
      .from('audit_events')
      .select(EVENT_COLUMNS)
      .eq('process_id', processId)
      .in('action', [...PROCESS_EVENT_ACTIONS])
      .order('id', { ascending: true })
      .limit(limit)
      .retry(false);
    const { data, error, status } = await (after === undefined ? base : base.gt('id', after.id));
    if (error) {
      // A position the database cannot read (class 22: an id out of range) is the caller's cursor.
      if (after !== undefined && error.code?.startsWith(DATA_EXCEPTION_CLASS) === true) {
        throw invalidPosition(error.code);
      }
      throw upstreamFailure('read the process events', safeCause(error, status), status);
    }
    return parseRows(eventRowsSchema, data, 'the audit trail');
  }

  async function readStages(processId: string, stageIds: readonly string[]) {
    if (stageIds.length === 0) return [];
    const { data, error, status } = await supabase
      .from('process_stages')
      .select('id, position, name')
      .eq('process_id', processId)
      .in('id', [...stageIds])
      .retry(false);
    if (error) throw upstreamFailure('read the event stages', safeCause(error, status), status);
    return parseRows(stageRowsSchema, data, 'the stages table');
  }

  async function readActors(actorIds: readonly string[]): Promise<ProcessEventActor[]> {
    if (actorIds.length === 0) return [];
    const { data, error, status } = await supabase
      .from('profiles')
      .select('id, display_name')
      .in('id', [...actorIds])
      .retry(false);
    if (error) throw upstreamFailure('read the event actors', safeCause(error, status), status);
    return parseRows(profileRowsSchema, data, 'the profiles table').map((row) => ({
      id: row.id,
      displayName: row.display_name,
    }));
  }

  return {
    async list(processId, { limit, after }: ProcessEventQuery): Promise<ProcessEventPage | null> {
      if (!(await processExists(processId))) return null;

      // One extra row tells whether another page exists.
      const rows = await readEventRows(processId, limit + 1, after);
      const pageRows = rows.slice(0, limit);

      const stageIds = [
        ...new Set(
          pageRows.filter((row) => row.action === STAGE_APPROVED).map((row) => row.resource_id),
        ),
      ];
      const actorIds = [
        ...new Set(pageRows.flatMap((row) => (row.actor_id === null ? [] : [row.actor_id]))),
      ];
      const [stages, actors] = await Promise.all([
        readStages(processId, stageIds),
        readActors(actorIds),
      ]);
      const stageById = new Map(stages.map((stage) => [stage.id, stage]));
      const actorById = new Map(actors.map((actor) => [actor.id, actor]));

      const items = pageRows.map((row): ProcessEvent => ({
        id: String(row.id),
        occurredAt: new Date(row.occurred_at),
        action: row.action,
        actor: row.actor_id === null ? null : (actorById.get(row.actor_id) ?? null),
        details: detailsOf(row, stageById),
      }));

      const last = pageRows.at(-1);
      return {
        items,
        next: rows.length > limit && last !== undefined ? { id: String(last.id) } : null,
      };
    },
  };
}
