// A door to the LOCAL database for the few things the API tests cannot do through the API: move time
// and play the operator (Wave 6.1 owns this file). The temporary password of a login is valid for 72 h,
// and a test cannot wait for it; the validity runs from `private.password_baselines.recorded_at`, a
// private table that PostgREST does not expose and that no API role (the secret key included) may
// touch. The same goes for `private.mfa_first_activations`, which only the operator's MFA reset (E-25,
// Wave 11) deletes.
//
// It runs `psql` INSIDE the stack's `db` container (`docker exec`, no shell). The container is named
// `supabase_db_<project_id>`, with the `project_id` of `supabase/config.toml`, so it depends on nothing
// but the `db` container, which every stack has, whichever services were left out of `supabase start`
// (CI leaves out several). It does not go through `supabase db query`: that command answers differently
// depending on whether it thinks an AI agent is running it (a `{ rows }` object with a warning, or a bare
// array), and CI is not one. The statement is wrapped so that the database itself returns the rows as one
// JSON array, which is all that is parsed. Test code only: nothing in `src/` may import it (ESLint
// enforces it).
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { z } from 'zod';
import { LOGIN_GLOBAL_BUDGET } from '@/modules/identity/presentation/rate-limit-budgets';

const execFileAsync = promisify(execFile);

const CONFIG_PATH = fileURLToPath(new URL('../../supabase/config.toml', import.meta.url));
const QUERY_TIMEOUT_MS = 30_000;
const QUERY_MAX_BUFFER_BYTES = 1024 * 1024;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_HOURS = 24 * 365;
/** The characters a Supabase project id (and so a container name) is made of. */
const PROJECT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;

/** The `project_id` of a `config.toml`: it names the containers (`supabase_db_<project_id>`). */
export function parseProjectId(toml: string): string {
  const id = /^project_id\s*=\s*"([^"\n]+)"/m.exec(toml)?.[1];
  if (id === undefined || !PROJECT_ID_PATTERN.test(id)) {
    throw new Error('supabase/config.toml has no usable project_id');
  }
  return id;
}

/** The name of the `db` container of the stack of this repository. */
export function dbContainerName(toml: string = readFileSync(CONFIG_PATH, 'utf8')): string {
  return `supabase_db_${parseProjectId(toml)}`;
}

/**
 * The rows `psql` printed: ONE JSON array (see `queryLocal`). Anything else (no output, an object, text)
 * throws instead of being guessed at: a helper that guessed would test nothing.
 */
export function parseRowsOutput(stdout: string): Record<string, unknown>[] {
  let value: unknown;
  try {
    value = JSON.parse(stdout.trim());
  } catch {
    throw new Error('the database container answered something that is not a JSON array of rows');
  }
  const rows = z.array(z.record(z.string(), z.unknown())).safeParse(value);
  if (!rows.success) {
    throw new Error('the database container answered something that is not a JSON array of rows');
  }
  return rows.data;
}

/**
 * The arguments of `docker exec` that run one statement with psql as the operator, inside the `db`
 * container. `-c` hands the statement over as ONE argument (no shell, nothing to quote);
 * `ON_ERROR_STOP` makes a failing statement fail the command.
 */
function psqlArgs(statement: string): string[] {
  return [
    'exec',
    '-i',
    dbContainerName(),
    'psql',
    '-U',
    'postgres',
    '-d',
    'postgres',
    '-X',
    '-q',
    '-A',
    '-t',
    '-v',
    'ON_ERROR_STOP=1',
    '-c',
    statement,
  ];
}

/**
 * Runs one statement that returns rows (a SELECT, or an UPDATE or DELETE with RETURNING) against the
 * local database and returns them. The statement goes in a data-modifying CTE so that the database
 * itself folds the rows into one JSON array: no column separators, no command tags, no psql formatting
 * to parse. Callers build the statement from validated values only.
 */
async function queryLocal(sql: string): Promise<Record<string, unknown>[]> {
  const wrapped = `WITH r AS (${sql}) SELECT coalesce(json_agg(r), '[]'::json) FROM r`;
  let stdout: string;
  try {
    ({ stdout } = await execFileAsync('docker', psqlArgs(wrapped), {
      timeout: QUERY_TIMEOUT_MS,
      maxBuffer: QUERY_MAX_BUFFER_BYTES,
    }));
  } catch {
    // Deliberately not echoed: what psql or docker print could carry the statement or connection details.
    throw new Error('the query in the database container failed. Is the stack running?');
  }
  return parseRowsOutput(stdout);
}

function assertUuid(userId: string, what: string): void {
  if (!UUID_PATTERN.test(userId)) throw new Error(`${what}: the user id is not a UUID`);
}

/**
 * Makes the temporary password of `userId` `hours` hours old (the record `private.password_baselines`
 * is the one the 72 h validity reads, ADR 0013). Both arguments are validated before they reach the
 * SQL text: a UUID and a whole number of hours.
 */
export async function agePasswordBaseline(userId: string, hours: number): Promise<void> {
  assertUuid(userId, 'agePasswordBaseline');
  if (!Number.isInteger(hours) || hours < 0 || hours > MAX_HOURS) {
    throw new Error('agePasswordBaseline: the age is not a whole number of hours');
  }
  const rows = await queryLocal(
    `UPDATE private.password_baselines SET recorded_at = now() - interval '${hours} hours' ` +
      `WHERE user_id = '${userId}' RETURNING user_id`,
  );
  // A user with no temporary-password record would silently test nothing: fail the helper instead.
  if (rows.length !== 1) {
    throw new Error('agePasswordBaseline: the user has no temporary-password record to age');
  }
}

/**
 * What the operator's MFA reset (E-25, Wave 11) does to the database: deletes the mark of the user's
 * first activation (`private.mfa_first_activations`), the one thing that reopens the enrollment of a
 * new factor after the first one was activated (F-64). Returns whether there was a mark to delete.
 */
export async function resetFirstActivation(userId: string): Promise<boolean> {
  assertUuid(userId, 'resetFirstActivation');
  const rows = await queryLocal(
    `DELETE FROM private.mfa_first_activations WHERE user_id = '${userId}' RETURNING user_id`,
  );
  return rows.length === 1;
}

/** The factor whose activation created the user's first-activation mark, or `undefined` if none (F-73). */
export async function firstActivationFactorOf(userId: string): Promise<string | undefined> {
  assertUuid(userId, 'firstActivationFactorOf');
  const rows = await queryLocal(
    `SELECT factor_id FROM private.mfa_first_activations WHERE user_id = '${userId}'`,
  );
  const row = z.array(z.object({ factor_id: z.string() })).parse(rows)[0];
  return row?.factor_id;
}

/** What the activation trigger wrote into the registry for a factor (F-73): the proof of the activation. */
export async function activationProofOf(
  factorId: string,
): Promise<{ byBackend: boolean | null; hasChallenge: boolean; hasInstant: boolean } | undefined> {
  assertUuid(factorId, 'activationProofOf');
  const rows = await queryLocal(
    `SELECT proof_by_backend, proof_challenge_id IS NOT NULL AS has_challenge, ` +
      `proof_verified_at IS NOT NULL AS has_instant ` +
      `FROM private.mfa_backend_factors WHERE factor_id = '${factorId}'`,
  );
  const row = z
    .array(
      z.object({
        proof_by_backend: z.boolean().nullable(),
        has_challenge: z.boolean(),
        has_instant: z.boolean(),
      }),
    )
    .parse(rows)[0];
  return row === undefined
    ? undefined
    : {
        byBackend: row.proof_by_backend,
        hasChallenge: row.has_challenge,
        hasInstant: row.has_instant,
      };
}

/**
 * The ids of the challenges the backend recorded for a user. They stay on the server: the oracle check
 * tells the backend's challenges from the ones made at Auth by them, so a test uses this to prove that no
 * response and no log line carries one (F-63).
 */
export async function backendChallengeIdsOf(userId: string): Promise<string[]> {
  assertUuid(userId, 'backendChallengeIdsOf');
  const rows = await queryLocal(
    `SELECT challenge_id FROM private.mfa_backend_challenges WHERE user_id = '${userId}'`,
  );
  return z
    .array(z.object({ challenge_id: z.string() }))
    .parse(rows)
    .map((row) => row.challenge_id);
}

// ------------------------------------------------------------------ tracking fixtures (Wave 10) ----
// What the client panel tests need and no API route does yet (the "Ok" is Wave 9; a process with no
// stage or a tie in `created_at` is a state the functions never produce). They write as the operator
// (psql as postgres inside the db container, so as a SUPERUSER: the validation below is what keeps a
// test from running anything but these statements), NOT with the secret key: Wave 10.1 revokes the
// `service_role` DML on the tracking tables (F-81).
//
// Every value that reaches the SQL text is validated first: a UUID, a timestamp of one strict shape, a
// whole number or a plain label. No value the database RETURNS is ever put back into a statement: the
// ids are made here (`randomUUID`) or stay inside the database (a PL/pgSQL block), so a row in the
// database cannot become SQL (F-103). Each fixture is ONE statement, so it commits whole or not at all.
//
// WHAT THESE ARE NOT. `approveCurrentStageAsFixture` writes the rows an approval leaves and nothing
// else: no `audit_events` row (so no `stage.approved` on the timeline), none of the checks of the real
// function (no role, no `aal2`, no `expectedStageId`), and it is not a check of I5 or I6. It must not be
// used to test the timeline, the audit trail or the approval itself. Wave 9's `approve_current_stage`
// replaces it as soon as a test needs more than "this stage is completed and approved".

/** `2026-03-03T10:00:00.123456+00:00`: the shape PostgREST shows, with any sub-second precision. */
const TIMESTAMP_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/;
const LABEL_PATTERN = /^[A-Za-z0-9 ]{1,40}$/;
const MAX_FIXTURE_PROCESSES = 50;
/** The reason a fixture's own `RAISE EXCEPTION` carries: text of ours, never data, so it may be shown. */
const FIXTURE_REASON_PATTERN = /ERROR:\s+fixture: ([A-Za-z ,]{1,80})/;

function assertTimestamp(value: string, what: string): void {
  if (!TIMESTAMP_PATTERN.test(value))
    throw new Error(`${what}: the instant is not an ISO timestamp`);
}

function assertLabel(value: string, what: string): void {
  if (!LABEL_PATTERN.test(value)) throw new Error(`${what}: the label is not plain text`);
}

/**
 * The reason a fixture was refused, when it was refused by its own `RAISE EXCEPTION fixture: ...` (a
 * process that is not active, a stage that is not there). Anything else psql prints can carry the
 * statement or connection details, so only this one sentence is ever read out of it.
 */
export function fixtureReasonOf(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) return undefined;
  const { stderr } = error as { stderr?: unknown };
  return typeof stderr === 'string' ? FIXTURE_REASON_PATTERN.exec(stderr)?.[1]?.trim() : undefined;
}

/** Runs one statement that returns no rows. Atomic: a single statement is its own transaction. */
async function execLocal(sql: string): Promise<void> {
  let refusal: { readonly reason: string | undefined } | undefined;
  try {
    await execFileAsync('docker', psqlArgs(sql), {
      timeout: QUERY_TIMEOUT_MS,
      maxBuffer: QUERY_MAX_BUFFER_BYTES,
    });
  } catch (error) {
    refusal = { reason: fixtureReasonOf(error) };
  }
  if (refusal === undefined) return;
  // Deliberately without the caught error as `cause`: what psql or docker print can carry the statement
  // or connection details. Only the sentence the fixture raised itself is shown.
  throw new Error(
    refusal.reason === undefined
      ? 'the statement in the database container failed. Is the stack running?'
      : `the fixture was refused: ${refusal.reason}`,
  );
}

/**
 * The statement of `approveCurrentStageAsFixture`: ONE `DO` block, so the whole "Ok" commits or none of
 * it does. It locks the process row with `FOR NO KEY UPDATE` (the lock the real function takes) and
 * refuses a process that is not `active`; completes the stage in progress, records the approval, then
 * starts the next stage or, after the last, completes the process. The ids it works with never leave the
 * database.
 */
export function approveCurrentStageSql(processId: string, approverId: string): string {
  assertUuid(processId, 'approveCurrentStageAsFixture');
  assertUuid(approverId, 'approveCurrentStageAsFixture');
  return [
    'DO $fixture$',
    'DECLARE',
    '  v_stage_id uuid;',
    '  v_position smallint;',
    'BEGIN',
    `  PERFORM 1 FROM public.processes WHERE id = '${processId}' AND status = 'active' FOR NO KEY UPDATE;`,
    "  IF NOT FOUND THEN RAISE EXCEPTION 'fixture: the process is not active'; END IF;",
    "  UPDATE public.process_stages SET status = 'completed', completed_at = now()",
    `    WHERE process_id = '${processId}' AND status = 'in_progress'`,
    '    RETURNING id, position INTO v_stage_id, v_position;',
    "  IF NOT FOUND THEN RAISE EXCEPTION 'fixture: the process has no stage in progress'; END IF;",
    '  INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by)',
    `    VALUES (v_stage_id, '${processId}', '${approverId}');`,
    "  UPDATE public.process_stages SET status = 'in_progress', started_at = now()",
    `    WHERE process_id = '${processId}' AND position = v_position + 1;`,
    '  IF FOUND THEN',
    `    UPDATE public.processes SET updated_at = now(), version = version + 1 WHERE id = '${processId}';`,
    '  ELSE',
    "    UPDATE public.processes SET status = 'completed', completed_at = now(), updated_at = now(),",
    `      version = version + 1 WHERE id = '${processId}';`,
    '  END IF;',
    'END',
    '$fixture$',
  ].join('\n');
}

/**
 * Plays the "Ok" the way `approve_current_stage` will (Wave 9) for a process created through the API:
 * completes the stage in progress with an approval by `approverId` and starts the next one, or, after
 * the last, completes the process. It exists so the client panel can be read in the states an approval
 * makes (a completed stage, a completed process) before that function exists. Fails the helper when the
 * process is not active or has no stage in progress. See the note above on what it is not.
 */
export async function approveCurrentStageAsFixture(
  processId: string,
  approverId: string,
): Promise<void> {
  await execLocal(approveCurrentStageSql(processId, approverId));
}

/**
 * The statement of `insertProcessesAtFixture`: ONE statement (a data-modifying CTE at the top level), so
 * the processes and their stages commit together. The ids are the ones given, made here.
 */
export function insertProcessesAtSql(
  clientId: string,
  createdAt: string,
  label: string,
  ids: readonly string[],
): string {
  assertUuid(clientId, 'insertProcessesAtFixture');
  assertTimestamp(createdAt, 'insertProcessesAtFixture');
  assertLabel(label, 'insertProcessesAtFixture');
  ids.forEach((id) => assertUuid(id, 'insertProcessesAtFixture'));
  const list = ids.map((id) => `'${id}'`).join(', ');
  return (
    `WITH p AS (INSERT INTO public.processes (id, client_id, title, created_at, updated_at) ` +
    `SELECT t.id, '${clientId}', '${label} ' || t.n, '${createdAt}', '${createdAt}' ` +
    `FROM unnest(ARRAY[${list}]::uuid[]) WITH ORDINALITY AS t(id, n) RETURNING id) ` +
    `INSERT INTO public.process_stages (process_id, position, name, status, started_at) ` +
    `SELECT id, 1, 'Unica', 'in_progress', '${createdAt}' FROM p`
  );
}

/**
 * Inserts `count` processes of a client that all carry the same creation instant (the tie a keyset on
 * `created_at` alone gets wrong), each with ONE stage in progress, so the read side accepts them, in one
 * transaction. Titles are `<label> 1` to `<label> <count>`. Returns the ids in the order the list shows
 * equals (`id` ascending).
 */
export async function insertProcessesAtFixture(
  clientId: string,
  createdAt: string,
  count: number,
  label: string,
): Promise<string[]> {
  if (!Number.isInteger(count) || count < 1 || count > MAX_FIXTURE_PROCESSES) {
    throw new Error('insertProcessesAtFixture: the count is not a whole number from 1 to 50');
  }
  const ids = Array.from({ length: count }, () => randomUUID());
  await execLocal(insertProcessesAtSql(clientId, createdAt, label, ids));
  return ids.sort();
}

/**
 * Inserts a process of a client with NO stage: the corrupt state the read side must refuse to show (I1,
 * 500). The functions never produce it; only a hand-made row does. Returns its id; remove it with
 * `deleteProcessFixture` when the test is over.
 */
export async function insertProcessWithoutStagesFixture(
  clientId: string,
  label: string,
): Promise<string> {
  assertUuid(clientId, 'insertProcessWithoutStagesFixture');
  assertLabel(label, 'insertProcessWithoutStagesFixture');
  const id = randomUUID();
  await execLocal(
    `INSERT INTO public.processes (id, client_id, title) VALUES ('${id}', '${clientId}', '${label}')`,
  );
  return id;
}

/** The statement of `deleteProcessFixture`: one `DELETE` of one process, by id. */
export function deleteProcessSql(processId: string): string {
  assertUuid(processId, 'deleteProcessFixture');
  return `DELETE FROM public.processes WHERE id = '${processId}' RETURNING id`;
}

/**
 * Deletes a process the fixtures above inserted (its stages and approvals go with it), so a corrupt row
 * does not outlive its test in a database a developer keeps. Returns whether there was a row to delete.
 * Meant for fixture processes: the audit events of a process made by the functions stay behind
 * (the trail is append-only) and would then point at nothing.
 */
export async function deleteProcessFixture(processId: string): Promise<boolean> {
  const rows = await queryLocal(deleteProcessSql(processId));
  return rows.length === 1;
}

/** The name of a counter group (`login`, `totp-verify-daily`): lowercase words joined by hyphens. */
const BUDGET_GROUP_PATTERN = /^[a-z][a-z0-9-]{0,39}$/;

/**
 * The statement that deletes every counter of ONE global budget (scope `global`, spec §3.9). The bucket
 * of a counter is `<scope>:<group>:<hmac of the subject>` (`rateLimitBucket` plus the keyed subject), so
 * the budget's counters are the rows whose bucket starts with `global:<group>:`. The prefix is compared
 * with `left()` and not with `LIKE`, so no character of it is a pattern; and the group is checked
 * against a plain-name pattern, so nothing but `[a-z0-9:-]` ever reaches the SQL text.
 */
export function globalBudgetResetSql(group: string): string {
  if (!BUDGET_GROUP_PATTERN.test(group)) {
    throw new Error('globalBudgetResetSql: the group is not a plain counter group name');
  }
  const prefix = `global:${group}:`;
  return (
    `DELETE FROM private.rate_limit_counters WHERE left(bucket, ${prefix.length}) = '${prefix}' ` +
    'RETURNING bucket'
  );
}

/**
 * Empties the global login budget (`LOGIN_GLOBAL_BUDGET`: 300 sign-ins per 5 minutes for the whole
 * app, F-02) and returns how many counters it dropped. A full `test:api` run signs in for about as many
 * users as the budget allows, so a run that adds CEOs would hit the cap and answer 429 where a real
 * deployment would not; `tests/setup/reset-login-budget.ts` calls this before every test FILE. It is
 * safe only because the `api` project runs its files one at a time (`fileParallelism: false`) and
 * because the tests of the cap itself fill the budget inside one file. No argument: nothing a caller
 * passes ever reaches the SQL.
 */
export async function resetGlobalLoginBudget(): Promise<number> {
  const rows = await queryLocal(globalBudgetResetSql(LOGIN_GLOBAL_BUDGET.group));
  return rows.length;
}
