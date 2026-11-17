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
 * What the operator's password reset of a CEO (F-41, Wave 11) will do to the database: gives the user the
 * temporary password again (`must_change_password = true`), which a CEO that already enrolled its second
 * factor can only get this way. Returns whether the profile was there. A test that needs a CEO in that state
 * uses it, because the API has no route that produces it (`require_password_change` acts on client logins).
 */
export async function markPasswordPendingFixture(userId: string): Promise<boolean> {
  assertUuid(userId, 'markPasswordPendingFixture');
  const rows = await queryLocal(
    `UPDATE public.profiles SET must_change_password = true WHERE id = '${userId}' RETURNING id`,
  );
  return rows.length === 1;
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
 * transaction. Titles are `<label> 1` to `<label> <count>`. Returns the ids and titles in the order the
 * list shows equals (`id` ascending).
 */
export async function insertTitledProcessesAtFixture(
  clientId: string,
  createdAt: string,
  count: number,
  label: string,
): Promise<{ id: string; title: string }[]> {
  if (!Number.isInteger(count) || count < 1 || count > MAX_FIXTURE_PROCESSES) {
    throw new Error('insertProcessesAtFixture: the count is not a whole number from 1 to 50');
  }
  const ids = Array.from({ length: count }, () => randomUUID());
  await execLocal(insertProcessesAtSql(clientId, createdAt, label, ids));
  // the statement numbers the titles in the order of `ids` (WITH ORDINALITY): the same order here
  return ids
    .map((id, index) => ({ id, title: `${label} ${index + 1}` }))
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/** `insertTitledProcessesAtFixture` for a test that needs the ids only. */
export async function insertProcessesAtFixture(
  clientId: string,
  createdAt: string,
  count: number,
  label: string,
): Promise<string[]> {
  const inserted = await insertTitledProcessesAtFixture(clientId, createdAt, count, label);
  return inserted.map((row) => row.id);
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

/** The name of a database routine (`approve_current_stage`): lowercase words joined by underscores. */
const ROUTINE_PATTERN = /^[a-z][a-z0-9_]{0,62}$/;
/** A Postgres backend pid is an OS process id: a positive 32-bit integer. */
const MAX_BACKEND_PID = 2 ** 31 - 1;

function assertBackendPid(pid: number, what: string): void {
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > MAX_BACKEND_PID) {
    throw new Error(`${what}: the pid is not a positive integer`);
  }
}

/**
 * The statement that counts the backends of this database that are WAITING FOR A LOCK while running a
 * statement that names `routine`, and that are blocked by the session with pid `blockerPid`, directly or
 * through other waiters (Wave 9: requests parked behind a lock that a test holds in a second session).
 * A test uses it to know that every request it fired is blocked inside the function, so the requests are
 * truly simultaneous, without a sleep and without guessing a delay.
 *
 * "Blocked by the held session" is the recursive part. Row-lock waiters queue: the first waits for the
 * transaction that holds the row, and the next ones wait for the first (`pg_blocking_pids` names the
 * first, not the holder). An approval parked behind the held session holds the process lock, so a
 * cancellation parked behind THAT approval is blocked by the held session too, through it: counting only
 * the direct waiters would miss exactly the case the lock-order test is about. Anything not blocked by
 * the held session, another test's or another process's requests included, is not counted.
 *
 * The routine is checked against a plain-routine-name pattern and compared with `position()`, so no
 * character of it is a pattern; the pid is a validated positive integer. Nothing else reaches the SQL.
 */
export function lockWaitersSql(routine: string, blockerPid: number): string {
  if (!ROUTINE_PATTERN.test(routine)) {
    throw new Error('lockWaitersSql: the routine is not a plain routine name');
  }
  assertBackendPid(blockerPid, 'lockWaitersSql');
  return (
    'WITH RECURSIVE blocked (pid) AS (' +
    'SELECT a.pid FROM pg_stat_activity a ' +
    `WHERE a.datname = current_database() AND ${blockerPid} = ANY (pg_blocking_pids(a.pid)) ` +
    'UNION ' +
    'SELECT a.pid FROM pg_stat_activity a JOIN blocked b ON b.pid = ANY (pg_blocking_pids(a.pid)) ' +
    'WHERE a.datname = current_database()' +
    ') ' +
    'SELECT count(*)::int AS waiting FROM pg_stat_activity a JOIN blocked b ON b.pid = a.pid ' +
    `WHERE a.wait_event_type = 'Lock' AND position('${routine}' IN a.query) > 0`
  );
}

/**
 * How many backends are waiting for a lock inside a statement that names `routine`, blocked by the
 * session `blockerPid` (see `lockWaitersSql`).
 */
export async function countLockWaiters(routine: string, blockerPid: number): Promise<number> {
  const rows = await queryLocal(lockWaitersSql(routine, blockerPid));
  const row = z.array(z.object({ waiting: z.number().int().nonnegative() })).parse(rows)[0];
  if (row === undefined) throw new Error('countLockWaiters: the database counted nothing');
  return row.waiting;
}

/**
 * The statement that ends a held session from the database side (Wave 9, F-108): the test's psql was
 * started by a test and nothing else may own it, so it is matched by user and application name as well
 * as by pid, and a pid that was recycled by another backend (PostgREST connects as `authenticator`) is
 * never touched. A pid that is already gone matches no row.
 */
export function terminateBackendSql(pid: number): string {
  assertBackendPid(pid, 'terminateBackendSql');
  return (
    'SELECT pg_terminate_backend(a.pid) AS terminated FROM pg_stat_activity a ' +
    `WHERE a.pid = ${pid} AND a.pid <> pg_backend_pid() AND a.usename = 'postgres' ` +
    "AND a.application_name = 'psql'"
  );
}

/** Ends a held session by pid, whatever state its psql client is in (see `terminateBackendSql`). */
export async function terminateBackend(pid: number): Promise<void> {
  await queryLocal(terminateBackendSql(pid));
}

/** The approvals of a process, oldest first. */
export type ApprovalRow = {
  id: string;
  process_stage_id: string;
  process_id: string;
  approved_by: string;
  approved_at: string;
};

const approvalRowsSchema = z.array(
  z.object({
    id: z.string(),
    process_stage_id: z.string(),
    process_id: z.string(),
    approved_by: z.string(),
    approved_at: z.string(),
  }),
);

/**
 * The approvals of a process, oldest first, read in the database container. A read for a test to CHECK
 * a response against, never a way to produce one; it does not go through the secret key, which may lose
 * its access to `stage_approvals` (Wave 10.1, F-81).
 */
export async function readApprovalRows(processId: string): Promise<ApprovalRow[]> {
  assertUuid(processId, 'readApprovalRows');
  const rows = await queryLocal(
    'SELECT id, process_stage_id, process_id, approved_by, approved_at FROM public.stage_approvals ' +
      `WHERE process_id = '${processId}' ORDER BY approved_at, id`,
  );
  return approvalRowsSchema.parse(rows);
}

const auditIdRowsSchema = z.array(
  z.object({ id: z.number().int().positive(), action: z.string(), resource_id: z.string() }),
);

/** The audit events of a process with their ids, oldest id first, read in the database container. */
export async function readAuditIds(
  processId: string,
): Promise<{ id: number; action: string; resource_id: string }[]> {
  assertUuid(processId, 'readAuditIds');
  const rows = await queryLocal(
    'SELECT id, action, resource_id FROM public.audit_events ' +
      `WHERE process_id = '${processId}' ORDER BY id`,
  );
  return auditIdRowsSchema.parse(rows);
}

// ------------------------------------------- tracking fixtures and reads (Wave 10.1, F-81) ----
// The secret key no longer has any privilege on `clients`, `processes`, `process_stages` or
// `stage_approvals` (migration `tracking_service_role_revoke`), so every fixture that writes them, and
// every check that reads them past RLS, runs here as the operator, with the same discipline as above:
// a UUID, a timestamp of one strict shape, a small whole number, or a text that goes into the statement
// as the HEX of its UTF-8 bytes (`textLiteral`), so no character of it is ever SQL. No value the database
// returns is put back into a statement.

const MAX_TEXT_BYTES = 16 * 1024;
const MAX_FIXTURE_CLIENTS = 50;

/**
 * SQL for a text value that cannot be anything but that text: the hex of its UTF-8 bytes, decoded by
 * the database. Quotes, backslashes, `$`, NBSP, a BOM or a full-width letter all arrive exactly as they
 * are, and nothing in them is ever parsed as SQL. Refuses an empty or oversized text.
 */
export function textLiteral(value: string, what: string): string {
  if (typeof value !== 'string' || value === '' || Buffer.byteLength(value) > MAX_TEXT_BYTES) {
    throw new Error(`${what}: the text is empty or too long`);
  }
  return `convert_from(decode('${Buffer.from(value, 'utf8').toString('hex')}', 'hex'), 'UTF8')`;
}

export type FixtureClientRow = { id: string; name: string };

function assertCount(count: number, max: number, what: string): void {
  if (!Number.isInteger(count) || count < 1 || count > max) {
    throw new Error(`${what}: the count is not a whole number from 1 to ${max}`);
  }
}

/**
 * The statement of `insertClientsFixture`: ONE multi-row `INSERT`, so every client gets the same
 * `created_at` (`now()` is the start of the transaction) unless an instant is given. The ids are the ones
 * given, made by the caller.
 */
export function insertClientsSql(rows: readonly FixtureClientRow[], createdAt?: string): string {
  const what = 'insertClientsFixture';
  if (rows.length === 0) throw new Error(`${what}: no client to insert`);
  if (createdAt !== undefined) assertTimestamp(createdAt, what);
  const values = rows.map((row) => {
    assertUuid(row.id, what);
    const name = textLiteral(row.name, what);
    return createdAt === undefined
      ? `('${row.id}', ${name})`
      : `('${row.id}', ${name}, '${createdAt}', '${createdAt}')`;
  });
  const columns = createdAt === undefined ? '(id, name)' : '(id, name, created_at, updated_at)';
  return `INSERT INTO public.clients ${columns} VALUES ${values.join(', ')}`;
}

/**
 * Inserts clients with the given names in ONE statement (same creation instant, or `createdAt` for all
 * of them) and returns them in the order a list shows equals (`id` ascending). The names are inserted
 * as they are, with no normalization: that is the point of a fixture.
 */
export async function insertClientsFixture(
  names: readonly string[],
  createdAt?: string,
): Promise<FixtureClientRow[]> {
  assertCount(names.length, MAX_FIXTURE_CLIENTS, 'insertClientsFixture');
  const rows = names.map((name) => ({ id: randomUUID(), name }));
  await execLocal(insertClientsSql(rows, createdAt));
  return rows.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

/** One client (a tenant) for a test. */
export async function insertClientFixture(name: string): Promise<FixtureClientRow> {
  const [row] = await insertClientsFixture([name]);
  if (row === undefined) throw new Error('insertClientFixture: the database inserted nothing');
  return row;
}

/** The statement of `archiveClientFixture`. */
export function archiveClientSql(clientId: string): string {
  assertUuid(clientId, 'archiveClientFixture');
  return `UPDATE public.clients SET archived_at = now() WHERE id = '${clientId}' RETURNING id`;
}

/** Archives a client as the operator (the API path of it is `PATCH /admin/clients`). */
export async function archiveClientFixture(clientId: string): Promise<void> {
  const rows = await queryLocal(archiveClientSql(clientId));
  if (rows.length !== 1) throw new Error('archiveClientFixture: there is no such client');
}

/** How many processes of each state `seedProcessesFixture` makes. */
export type SeedProcessCounts = { active?: number; completed?: number; cancelled?: number };

type SeedIds = Readonly<Record<'active' | 'completed' | 'cancelled', readonly string[]>>;

const SEED_STATES = [
  ['active', 'Ativo'],
  ['completed', 'Concluído'],
  ['cancelled', 'Cancelado'],
] as const;

/**
 * The statement of `seedProcessesFixture`: ONE statement with three chained data-modifying CTEs, so the
 * processes, their stage and the approvals of the completed ones commit together. Every process has ONE
 * stage that respects its state (I1 to I5): `in_progress` for an active process (I2) and for a cancelled
 * one (frozen where it stopped, I4), `completed` with an approval for a completed one (I3, I5).
 */
export function seedProcessesSql(
  clientId: string,
  ids: SeedIds,
  approverId: string | undefined,
): string {
  const what = 'seedProcessesFixture';
  assertUuid(clientId, what);
  if (approverId !== undefined) assertUuid(approverId, what);
  const values = SEED_STATES.flatMap(([status, label]) =>
    ids[status].map((id, index) => {
      assertUuid(id, what);
      const title = textLiteral(`${label} ${index + 1}`, what);
      const completedAt = status === 'completed' ? 'now()' : 'NULL::timestamptz';
      const cancelledAt = status === 'cancelled' ? 'now()' : 'NULL::timestamptz';
      return `('${id}'::uuid, '${clientId}'::uuid, ${title}, '${status}'::public.process_status, ${completedAt}, ${cancelledAt})`;
    }),
  );
  if (values.length === 0) throw new Error(`${what}: no process to insert`);
  return [
    'WITH p AS (',
    '  INSERT INTO public.processes (id, client_id, title, status, completed_at, cancelled_at)',
    `  VALUES ${values.join(', ')}`,
    '  RETURNING id, status',
    '), s AS (',
    '  INSERT INTO public.process_stages (process_id, position, name, status, started_at, completed_at)',
    "  SELECT id, 1, 'Unica',",
    "         CASE WHEN status = 'completed' THEN 'completed' ELSE 'in_progress' END::public.stage_status,",
    "         now(), CASE WHEN status = 'completed' THEN now() END",
    '    FROM p',
    '  RETURNING id, process_id, status',
    ')',
    'INSERT INTO public.stage_approvals (process_stage_id, process_id, approved_by)',
    `SELECT s.id, s.process_id, ${approverId === undefined ? 'NULL::uuid' : `'${approverId}'::uuid`}`,
    "  FROM s WHERE s.status = 'completed'",
  ].join('\n');
}

/**
 * Gives a client processes in the given states, each with a stage that respects the invariants of its
 * state (the read side refuses a process that does not). `approverId` (a CEO) is required when any
 * process is completed: the approval of its stage names who approved it.
 */
export async function seedProcessesFixture(
  clientId: string,
  counts: SeedProcessCounts,
  approverId?: string,
): Promise<void> {
  const ids: SeedIds = {
    active: Array.from({ length: counts.active ?? 0 }, () => randomUUID()),
    completed: Array.from({ length: counts.completed ?? 0 }, () => randomUUID()),
    cancelled: Array.from({ length: counts.cancelled ?? 0 }, () => randomUUID()),
  };
  const total = ids.active.length + ids.completed.length + ids.cancelled.length;
  if (total === 0) return;
  assertCount(total, MAX_FIXTURE_PROCESSES, 'seedProcessesFixture');
  if (ids.completed.length > 0 && approverId === undefined) {
    throw new Error('seedProcessesFixture: a completed process needs the CEO who approved it');
  }
  await execLocal(seedProcessesSql(clientId, ids, approverId));
}

const countRowsSchema = z.array(z.object({ n: z.number().int().nonnegative() }));

async function countOf(sql: string): Promise<number> {
  const row = countRowsSchema.parse(await queryLocal(sql))[0];
  if (row === undefined) throw new Error('the database counted nothing');
  return row.n;
}

/** How many clients exist, past RLS (a fixture check, never a behavior). */
export async function countClients(): Promise<number> {
  return countOf('SELECT count(*)::int AS n FROM public.clients');
}

/** How many clients carry exactly this name. */
export async function countClientsNamed(name: string): Promise<number> {
  return countOf(
    `SELECT count(*)::int AS n FROM public.clients WHERE name = ${textLiteral(name, 'countClientsNamed')}`,
  );
}

const clientRowSchema = z.object({
  id: z.string(),
  name: z.string(),
  archived_at: z.string().nullable(),
  created_at: z.string(),
  updated_at: z.string(),
});
export type ClientRow = z.infer<typeof clientRowSchema>;

/** The client row as the database holds it, or `undefined`. */
export async function readClientRow(clientId: string): Promise<ClientRow | undefined> {
  assertUuid(clientId, 'readClientRow');
  const rows = await queryLocal(
    'SELECT id, name, archived_at, created_at, updated_at FROM public.clients ' +
      `WHERE id = '${clientId}'`,
  );
  return z.array(clientRowSchema).parse(rows)[0];
}

/** How many processes a client has, in any state. */
export async function countProcessesOf(clientId: string): Promise<number> {
  assertUuid(clientId, 'countProcessesOf');
  return countOf(`SELECT count(*)::int AS n FROM public.processes WHERE client_id = '${clientId}'`);
}

/** The titles of a client's processes, oldest first. */
export async function readProcessTitlesOf(clientId: string): Promise<string[]> {
  assertUuid(clientId, 'readProcessTitlesOf');
  const rows = await queryLocal(
    `SELECT title FROM public.processes WHERE client_id = '${clientId}' ORDER BY created_at, id`,
  );
  return z
    .array(z.object({ title: z.string() }))
    .parse(rows)
    .map((row) => row.title);
}

/** How many processes carry exactly this title, whoever owns them. */
export async function countProcessesTitled(title: string): Promise<number> {
  return countOf(
    `SELECT count(*)::int AS n FROM public.processes WHERE title = ${textLiteral(title, 'countProcessesTitled')}`,
  );
}

const processRowSchema = z.object({
  id: z.string(),
  client_id: z.string(),
  title: z.string(),
  status: z.enum(['active', 'completed', 'cancelled']),
  version: z.number().int(),
  created_at: z.string(),
  updated_at: z.string(),
  completed_at: z.string().nullable(),
  cancelled_at: z.string().nullable(),
});
export type ProcessRow = z.infer<typeof processRowSchema>;

/** The process row as the database holds it. Throws when there is none. */
export async function readProcessRow(processId: string): Promise<ProcessRow> {
  assertUuid(processId, 'readProcessRow');
  const rows = await queryLocal(
    'SELECT id, client_id, title, status, version, created_at, updated_at, completed_at, ' +
      `cancelled_at FROM public.processes WHERE id = '${processId}'`,
  );
  const row = z.array(processRowSchema).parse(rows)[0];
  if (row === undefined) throw new Error('readProcessRow: there is no such process');
  return row;
}

const stageRowSchema = z.object({
  id: z.string(),
  position: z.number().int(),
  name: z.string(),
  description: z.string().nullable(),
  status: z.enum(['pending', 'in_progress', 'completed']),
  started_at: z.string().nullable(),
  completed_at: z.string().nullable(),
});
export type StageRow = z.infer<typeof stageRowSchema>;

/** The stages of a process in position order. */
export async function readStageRows(processId: string): Promise<StageRow[]> {
  assertUuid(processId, 'readStageRows');
  const rows = await queryLocal(
    'SELECT id, position, name, description, status, started_at, completed_at ' +
      `FROM public.process_stages WHERE process_id = '${processId}' ORDER BY position`,
  );
  return z.array(stageRowSchema).parse(rows);
}
