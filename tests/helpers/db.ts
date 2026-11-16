// A door to the LOCAL database for the one thing the API tests cannot do through the API: move time
// (Wave 6.1 owns this file). The temporary password of a login is valid for 72 h, and a test cannot
// wait for it; the validity runs from `private.password_baselines.recorded_at`, a private table that
// PostgREST does not expose and that no API role (the secret key included) may touch.
//
// It runs the project's own Supabase CLI (`supabase db query --local`, no shell), the way
// `tests/setup/local-env.ts` runs `supabase status`. `--local` is not a default but a flag: the CLI
// refuses to point it anywhere else, and the tests only ever run against a loopback stack. Test code
// only: nothing in `src/` may import it.
import { execFile } from 'node:child_process';
import { resolve } from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const SUPABASE_BIN = resolve(process.cwd(), 'node_modules/.bin/supabase');
const QUERY_TIMEOUT_MS = 30_000;
const QUERY_MAX_BUFFER_BYTES = 1024 * 1024;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_HOURS = 24 * 365;

/**
 * Makes the temporary password of `userId` `hours` hours old (the record `private.password_baselines`
 * is the one the 72 h validity reads, ADR 0013). Both arguments are validated before they reach the
 * SQL text: a UUID and a whole number of hours.
 */
export async function agePasswordBaseline(userId: string, hours: number): Promise<void> {
  if (!UUID_PATTERN.test(userId)) throw new Error('agePasswordBaseline: the user id is not a UUID');
  if (!Number.isInteger(hours) || hours < 0 || hours > MAX_HOURS) {
    throw new Error('agePasswordBaseline: the age is not a whole number of hours');
  }
  const sql =
    `UPDATE private.password_baselines SET recorded_at = now() - interval '${hours} hours' ` +
    `WHERE user_id = '${userId}' RETURNING user_id`;
  let stdout: string;
  try {
    ({ stdout } = await execFileAsync(SUPABASE_BIN, ['db', 'query', '--local', '-o', 'json', sql], {
      timeout: QUERY_TIMEOUT_MS,
      maxBuffer: QUERY_MAX_BUFFER_BYTES,
    }));
  } catch {
    // Deliberately not echoed: the CLI output could carry connection details.
    throw new Error(
      'agePasswordBaseline: "supabase db query --local" failed. Is the stack running?',
    );
  }
  // A user with no temporary-password record would silently test nothing: fail the helper instead.
  const answer = JSON.parse(stdout.slice(stdout.indexOf('{'))) as { rows?: unknown[] };
  if (answer.rows?.length !== 1) {
    throw new Error('agePasswordBaseline: the user has no temporary-password record to age');
  }
}
