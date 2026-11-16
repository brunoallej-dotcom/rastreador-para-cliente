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
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { z } from 'zod';

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
 * Runs one statement that returns rows (a SELECT, or an UPDATE or DELETE with RETURNING) against the
 * local database and returns them. The statement goes in a data-modifying CTE so that the database
 * itself folds the rows into one JSON array: no column separators, no command tags, no psql formatting
 * to parse. Callers build the statement from validated values only.
 */
async function queryLocal(sql: string): Promise<Record<string, unknown>[]> {
  const wrapped = `WITH r AS (${sql}) SELECT coalesce(json_agg(r), '[]'::json) FROM r`;
  let stdout: string;
  try {
    ({ stdout } = await execFileAsync(
      'docker',
      [
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
        wrapped,
      ],
      { timeout: QUERY_TIMEOUT_MS, maxBuffer: QUERY_MAX_BUFFER_BYTES },
    ));
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
