// A door to the LOCAL database for the few things the API tests cannot do through the API: move time
// and play the operator (Wave 6.1 owns this file). The temporary password of a login is valid for 72 h,
// and a test cannot wait for it; the validity runs from `private.password_baselines.recorded_at`, a
// private table that PostgREST does not expose and that no API role (the secret key included) may
// touch. The same goes for `private.mfa_first_activations`, which only the operator's MFA reset (E-25,
// Wave 11) deletes.
//
// It runs the project's own Supabase CLI (`supabase db query --local`, no shell), the way
// `tests/setup/local-env.ts` runs `supabase status`. `--local` is not a default but a flag: the CLI
// refuses to point it anywhere else, and the tests only ever run against a loopback stack. The binary and
// the working directory come from where this file is, not from `process.cwd()`. Test code only: nothing
// in `src/` may import it (ESLint enforces it).
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { z } from 'zod';

const execFileAsync = promisify(execFile);

const REPO_ROOT = fileURLToPath(new URL('../../', import.meta.url));
const SUPABASE_BIN = `${REPO_ROOT}node_modules/.bin/supabase`;
const QUERY_TIMEOUT_MS = 30_000;
const QUERY_MAX_BUFFER_BYTES = 1024 * 1024;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_HOURS = 24 * 365;

/** What `supabase db query -o json` prints: an object with the rows (plus a boundary and a warning). */
const queryAnswerSchema = z.looseObject({ rows: z.array(z.record(z.string(), z.unknown())) });

/**
 * The JSON object in the CLI output. The CLI may print progress lines before it ("Connecting to local
 * database...") and a notice after it (an update available), so each line that opens an object is tried
 * as the start, and each later line that ends with a closing brace as the end; the first slice that
 * parses and has the shape of an answer wins.
 */
export function parseQueryOutput(output: string): z.infer<typeof queryAnswerSchema> {
  const lines = output.split('\n');
  for (let start = 0; start < lines.length; start += 1) {
    if (lines[start]?.trimStart().startsWith('{') !== true) continue;
    for (let end = start; end < lines.length; end += 1) {
      if (lines[end]?.trimEnd().endsWith('}') !== true) continue;
      try {
        const slice = lines.slice(start, end + 1).join('\n');
        const answer = queryAnswerSchema.safeParse(JSON.parse(slice));
        if (answer.success) return answer.data;
      } catch {
        // not a complete object yet: try the next closing line
      }
    }
  }
  throw new Error('the output of "supabase db query" holds no answer with rows');
}

/** Runs one statement against the local database and returns the rows it RETURNING. */
async function queryLocal(sql: string): Promise<unknown[]> {
  let stdout: string;
  try {
    ({ stdout } = await execFileAsync(SUPABASE_BIN, ['db', 'query', '--local', '-o', 'json', sql], {
      cwd: REPO_ROOT,
      timeout: QUERY_TIMEOUT_MS,
      maxBuffer: QUERY_MAX_BUFFER_BYTES,
    }));
  } catch {
    // Deliberately not echoed: the CLI output could carry connection details.
    throw new Error('"supabase db query --local" failed. Is the stack running?');
  }
  return parseQueryOutput(stdout).rows;
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
