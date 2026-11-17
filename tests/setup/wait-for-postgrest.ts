// setupFiles of the `int` and `api` projects: before every test FILE, waits until PostgREST can read the
// database.
//
// Right after `supabase db reset` PostgREST has lost its connection to the database and answers every call
// with "Database client error. Retrying the connection." (a 503) until it reconnects, which takes a few
// seconds, longer than the start of a test run. The first files of a run then failed in their `beforeAll`
// (a CEO that could not change its password) while the next ones passed: a readiness race of the stack,
// not of the code under test. CI starts the stack once and never resets it, so there this costs one
// request per file.
//
// Bounded and deterministic: `vi.waitFor` polls a real read (a row of the default stage template, with
// the secret key: static data with no tenant in it, and the secret key has no access to the tracking
// tables since F-81) every 500 ms for at most 30 s, and the failure says what PostgREST last answered.
// It spends none of the budgets the tests care about (no login, no rate limiter) and writes nothing.
import { beforeAll, vi } from 'vitest';

const READY_TIMEOUT_MS = 30_000;
const POLL_INTERVAL_MS = 500;
const REQUEST_TIMEOUT_MS = 5_000;

/** One read of one row of the template. Throws what PostgREST answered (its `code` and `message`, never a secret). */
async function readOneTemplateRow(): Promise<void> {
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (url === undefined || secretKey === undefined) {
    throw new Error(
      'SUPABASE_URL and SUPABASE_SECRET_KEY are not set (tests/setup/apply-local-env.ts)',
    );
  }
  const response = await fetch(`${url}/rest/v1/default_stage_template?select=position&limit=1`, {
    headers: { apikey: secretKey, Authorization: `Bearer ${secretKey}` },
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  if (response.ok) return;
  const body = (await response.json().catch(() => null)) as {
    code?: unknown;
    message?: unknown;
  } | null;
  throw new Error(
    `PostgREST answered ${response.status}${typeof body?.code === 'string' ? ` ${body.code}` : ''}` +
      `${typeof body?.message === 'string' ? `: ${body.message}` : ''}`,
  );
}

beforeAll(async () => {
  try {
    await vi.waitFor(readOneTemplateRow, { timeout: READY_TIMEOUT_MS, interval: POLL_INTERVAL_MS });
  } catch (error) {
    const last = error instanceof Error ? error.message : String(error);
    throw new Error(
      `PostgREST could not read the database within ${READY_TIMEOUT_MS / 1000} s ` +
        `(right after \`db:reset\` it needs a few seconds; is the stack up?). Last answer: ${last}`,
      { cause: error },
    );
  }
});
