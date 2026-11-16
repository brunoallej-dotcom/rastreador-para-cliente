// A transaction held OPEN in a second database session (Wave 9 owns this file). It is how a test proves
// what a concurrent write does without a sleep and without hoping for a lucky interleaving: the test
// takes the lock the write functions take, fires its requests (they park behind it, which
// `countLockWaiters` in db.ts observes), and only then lets go. What happens next is decided by the
// database, the same way for every run.
//
//   const identity = ceoIdentityOf(ceo);                       // user id + session id of a CEO session
//   const held = await openHeldTransaction();
//   try {
//     await held.cancelProcess(identity, processId);           // the REAL update_process, not committed yet
//     const approving = approveViaApi(other.cookies, processId, { expectedStageId });
//     await waitForLockWaiters(held, 'approve_current_stage', 1);  // the approval is parked on the lock
//     await held.commit();                                     // the cancel lands; the approval goes on
//     expect((await approving).status).toBe(422);
//   } finally {
//     await held.abort();                                      // never leaves a lock behind
//   }
//
// The calls run the real functions as the real CEO: `SET LOCAL ROLE authenticated` plus the JWT claims
// and the request id that PostgREST would set, so `private.is_ceo()` sees the attested session the API
// login made and the audit rows it writes carry a `request_id` like the ones PostgREST makes. It runs
// `psql` inside the `db` container through `docker exec` (no shell), like `db.ts`, and prints nothing of
// what psql says: a failing statement ends the session, and the helper reports that and nothing else.
// Every value that reaches the SQL text is a validated UUID or a validated pid.
//
// A held session must never outlive its test (F-108): a lock left behind makes every later test of the
// machine wait for it. So the session limits itself inside the database (`lock_timeout`,
// `statement_timeout`, `idle_in_transaction_session_timeout`, all below the test timeout), and it is ended
// from both sides on open failure, on any failed step and in `abort()`: end of input to psql, a bounded
// wait for it to exit, a kill, and always a `pg_terminate_backend` of its pid from another connection.
// Test code only: nothing in `src/` may import it.
import { spawn } from 'node:child_process';
import { vi } from 'vitest';
import { countLockWaiters, dbContainerName, terminateBackend } from './db';
import { sessionIdOf } from './fixtures';
import { readSessionCookie, type CookieStore } from './http';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** What ends the wait for one batch of statements: psql echoes it after running them. */
const SENTINEL_PREFIX = '__held_transaction_step_';
/** Where the pid of the held session is printed: the first thing the session says. */
const PID_MARKER = 'held_backend_pid=';
/**
 * The limits of the held session, inside the database. They are below the 30 s `testTimeout`, so that a
 * session that is stuck fails with its own message and is rolled back by the database before vitest
 * gives up on the test: nothing waits for a lock longer than 5 s, nothing runs longer than 15 s, and an
 * open transaction that nobody talks to is rolled back after 25 s.
 */
const SESSION_LIMITS_SQL =
  "SET lock_timeout = '5s'; SET statement_timeout = '15s'; SET idle_in_transaction_session_timeout = '25s';";
/** A Postgres backend pid is an OS process id: a positive 32-bit integer (db.ts validates the same range). */
const MAX_BACKEND_PID = 2 ** 31 - 1;
/** One step (a batch of statements) that does not finish in this long ends the session. */
const STEP_TIMEOUT_MS = 10_000;
/** How long `shutdown` lets psql exit on its own, after end of input, before it kills it. */
const EXIT_WAIT_MS = 2_000;
/** Waiting for requests to park: 12 s, and 2 s of cleanup after it, stay below the 30 s test timeout. */
const WAIT_FOR_WAITERS_TIMEOUT_MS = 12_000;
const WAIT_FOR_WAITERS_INTERVAL_MS = 25;

/** Who the held session acts as: a CEO and the session the API attested for them. */
export type CeoIdentity = { readonly userId: string; readonly sessionId: string };

/** The identity of a CEO that logged in through the API: the user id and the `session_id` of the JWT. */
export function ceoIdentityOf(session: {
  readonly ceo: { readonly id: string };
  readonly cookies: CookieStore;
}): CeoIdentity {
  const { access_token: accessToken } = readSessionCookie(session.cookies);
  return { userId: session.ceo.id, sessionId: sessionIdOf(accessToken) };
}

function assertUuid(value: string, what: string): void {
  if (!UUID_PATTERN.test(value)) throw new Error(`held transaction: ${what} is not a UUID`);
}

/** The pid the session printed (`held_backend_pid=<n>`), or an error: a cleanup that guessed would leak. */
export function parseBackendPid(output: string): number {
  const text = new RegExp(`${PID_MARKER}([0-9]+)(?![0-9])`).exec(output)?.[1];
  const pid = text === undefined ? Number.NaN : Number(text);
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > MAX_BACKEND_PID) {
    throw new Error('held transaction: the session did not report its backend pid');
  }
  return pid;
}

/** The statement that makes the session print its own pid. */
export const REPORT_PID_SQL = `SELECT '${PID_MARKER}' || pg_backend_pid();`;

/** The statements that open the transaction: the limits first, then `BEGIN`. */
export const OPEN_TRANSACTION_SQL = `${SESSION_LIMITS_SQL} BEGIN;`;

/**
 * The statements that make the session the CEO: the role, the claims PostgREST would set, and the
 * request id header it would set (`private.request_id()` reads it), so a committed audit row has a
 * `request_id` like the rows the API writes.
 */
export function asCeoSql(identity: CeoIdentity): string {
  assertUuid(identity.userId, 'the user id');
  assertUuid(identity.sessionId, 'the session id');
  const claims = JSON.stringify({
    sub: identity.userId,
    role: 'authenticated',
    aal: 'aal2',
    session_id: identity.sessionId,
  });
  const headers = JSON.stringify({ 'x-request-id': 'held-transaction' });
  return (
    'SET LOCAL ROLE authenticated; ' +
    `SELECT set_config('request.jwt.claims', '${claims}', true); ` +
    `SELECT set_config('request.headers', '${headers}', true);`
  );
}

/** The row lock both write functions take first: the process row, FOR NO KEY UPDATE (F-82). */
export function lockProcessSql(processId: string): string {
  assertUuid(processId, 'the process id');
  return `SELECT id FROM public.processes WHERE id = '${processId}' FOR NO KEY UPDATE;`;
}

/**
 * The row lock `approve_current_stage` takes second: the stage row, FOR NO KEY UPDATE. Held ALONE, it is
 * how a test stops an approval after it has the process lock and before it has the stage: whoever
 * locks the stage before the process (the wrong order) is not stopped by it in the same place.
 */
export function lockStageSql(stageId: string): string {
  assertUuid(stageId, 'the stage id');
  return `SELECT id FROM public.process_stages WHERE id = '${stageId}' FOR NO KEY UPDATE;`;
}

/** `update_process` cancelling the process, as the CEO. */
export function cancelProcessSql(identity: CeoIdentity, processId: string): string {
  assertUuid(processId, 'the process id');
  return (
    `${asCeoSql(identity)} ` +
    `SELECT id FROM public.update_process('${processId}', NULL, true); RESET ROLE;`
  );
}

/** `approve_current_stage`, as the CEO. */
export function approveStageSql(
  identity: CeoIdentity,
  processId: string,
  expectedStageId: string,
): string {
  assertUuid(processId, 'the process id');
  assertUuid(expectedStageId, 'the stage id');
  return (
    `${asCeoSql(identity)} ` +
    `SELECT id FROM public.approve_current_stage('${processId}', '${expectedStageId}'); RESET ROLE;`
  );
}

export type HeldTransaction = {
  /** The backend pid of the held session: what `waitForLockWaiters` counts the blocked requests against. */
  readonly pid: number;
  /** Takes the process row lock the way the write functions do, as the database owner. */
  lockProcess(processId: string): Promise<void>;
  /** Takes ONLY the stage row lock (FOR NO KEY UPDATE), as the database owner. */
  lockStage(stageId: string): Promise<void>;
  /** Runs the REAL `update_process` that cancels the process; the transaction stays open. */
  cancelProcess(identity: CeoIdentity, processId: string): Promise<void>;
  /** Runs the REAL `approve_current_stage`; the transaction stays open. */
  approveStage(identity: CeoIdentity, processId: string, expectedStageId: string): Promise<void>;
  /** Commits, which releases every lock the transaction holds. */
  commit(): Promise<void>;
  /**
   * Ends the session whatever state it is in and rolls back what is still open: end of input, a bounded
   * wait, a kill, and a `pg_terminate_backend` from another connection. Safe to call twice and after
   * `commit`: put it in `finally`, and await it.
   */
  abort(): Promise<void>;
};

/**
 * Opens the session, `BEGIN`s, and reports its pid. Every method resolves once psql has run its
 * statements, and rejects if the session ended instead (a statement failed, the stack is not running,
 * a step took too long). A failure to open ends the session before the error reaches the test.
 */
export async function openHeldTransaction(): Promise<HeldTransaction> {
  const child = spawn(
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
    ],
    { stdio: ['pipe', 'pipe', 'ignore'] },
  );

  let output = '';
  let ended = false;
  let exitCode: number | null = null;
  const watchers = new Set<() => void>();
  const notify = () => watchers.forEach((watcher) => watcher());

  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk: string) => {
    output += chunk;
    notify();
  });
  child.on('exit', (code) => {
    ended = true;
    exitCode = code;
    notify();
  });
  child.on('error', () => {
    ended = true;
    notify();
  });
  // A write to a session that already ended is reported by `run` (which sees `ended`), not as an
  // unhandled stream error.
  child.stdin.on('error', () => undefined);

  let pid: number | undefined;

  /** Waits until `check` says so, the session ends, or `timeoutMs` passes; `null` means it timed out. */
  function waitFor(check: () => boolean, timeoutMs: number): Promise<'done' | 'ended' | 'timeout'> {
    return new Promise((resolve) => {
      const settle = (result: 'done' | 'ended' | 'timeout') => {
        clearTimeout(timer);
        watchers.delete(watcher);
        resolve(result);
      };
      const watcher = () => {
        if (check()) settle('done');
        else if (ended) settle('ended');
      };
      const timer = setTimeout(() => settle('timeout'), timeoutMs);
      watchers.add(watcher);
      watcher();
    });
  }

  /**
   * Ends the session from both sides (F-108). End of input makes psql quit and roll back; a bounded
   * wait lets it; a kill is for a hung one; and the backend is ALWAYS terminated from another
   * connection, which is what releases the locks even when the client never got the message.
   */
  async function shutdown(): Promise<void> {
    child.stdin.end();
    if ((await waitFor(() => ended, EXIT_WAIT_MS)) === 'timeout') child.kill('SIGKILL');
    if (pid !== undefined) await terminateBackend(pid);
  }

  let step = 0;
  /** Sends statements, then waits for psql to echo the sentinel that follows them. */
  async function runStep(statements: string): Promise<void> {
    if (ended) throw new Error('held transaction: the session is already over');
    step += 1;
    const sentinel = `${SENTINEL_PREFIX}${step}__`;
    child.stdin.write(`${statements}\n\\echo ${sentinel}\n`);
    const result = await waitFor(() => output.includes(sentinel), STEP_TIMEOUT_MS);
    if (result === 'timeout') throw new Error('held transaction: a step did not finish in time');
    if (result === 'ended')
      throw new Error('held transaction: the session ended: a statement failed');
  }

  /** A step whose failure, or timeout, ends the session before the error reaches the test. */
  async function run(statements: string): Promise<void> {
    try {
      await runStep(statements);
    } catch (error) {
      await shutdown();
      throw error;
    }
  }

  try {
    await runStep(REPORT_PID_SQL);
    pid = parseBackendPid(output);
    await runStep(OPEN_TRANSACTION_SQL);
  } catch (error) {
    await shutdown();
    throw error;
  }
  const backendPid = pid;

  return {
    pid: backendPid,
    lockProcess: (processId) => run(lockProcessSql(processId)),
    lockStage: (stageId) => run(lockStageSql(stageId)),
    cancelProcess: (identity, processId) => run(cancelProcessSql(identity, processId)),
    approveStage: (identity, processId, expectedStageId) =>
      run(approveStageSql(identity, processId, expectedStageId)),
    async commit() {
      await run('COMMIT;');
      child.stdin.end();
      const result = await waitFor(() => ended, EXIT_WAIT_MS);
      if (result === 'timeout' || exitCode !== 0) {
        await shutdown();
        throw new Error('held transaction: the session did not end cleanly');
      }
    },
    abort: shutdown,
  };
}

/**
 * Waits until at least `count` backends are blocked on a lock, directly or through other waiters, by
 * the held session, inside a statement that names `routine`: the requests a test fired are parked, so
 * they are simultaneous in the only sense that matters. It polls the database (`countLockWaiters`)
 * until that holds, with a bound: no fixed delay, and a request that never reaches the lock fails the
 * test with this message instead of hanging.
 */
export async function waitForLockWaiters(
  held: Pick<HeldTransaction, 'pid'>,
  routine: string,
  count: number,
): Promise<void> {
  await vi.waitFor(
    async () => {
      const waiting = await countLockWaiters(routine, held.pid);
      if (waiting < count) {
        throw new Error(`${waiting} of ${count} ${routine} calls are blocked by the held session`);
      }
    },
    { timeout: WAIT_FOR_WAITERS_TIMEOUT_MS, interval: WAIT_FOR_WAITERS_INTERVAL_MS },
  );
}
