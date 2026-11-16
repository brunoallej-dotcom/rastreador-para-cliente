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
//     await waitForLockWaiters('approve_current_stage', 1);    // the approval is parked on the lock
//     await held.commit();                                     // the cancel lands; the approval goes on
//     expect((await approving).status).toBe(422);
//   } finally {
//     held.abort();                                            // never leaves a lock behind
//   }
//
// The calls run the real functions as the real CEO: `SET LOCAL ROLE authenticated` plus the JWT claims
// that PostgREST would set (`sub`, `aal`, `session_id`), so `private.is_ceo()` sees the attested session
// the API login made. It runs `psql` inside the `db` container through `docker exec` (no shell), like
// `db.ts`, and prints nothing of what psql says: a failing statement ends the session, and the helper
// reports that and nothing else. Every value that reaches the SQL text is a validated UUID. Test code
// only: nothing in `src/` may import it.
import { spawn } from 'node:child_process';
import { vi } from 'vitest';
import { countLockWaiters, dbContainerName } from './db';
import { sessionIdOf } from './fixtures';
import { readSessionCookie, type CookieStore } from './http';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** What ends the wait for one batch of statements: psql echoes it after running them. */
const SENTINEL_PREFIX = '__held_transaction_step_';
/** A failsafe, inside the database: an abandoned held transaction is rolled back after this long. */
const IDLE_IN_TRANSACTION_LIMIT = '60s';
const STEP_TIMEOUT_MS = 20_000;
const WAIT_FOR_WAITERS_TIMEOUT_MS = 15_000;
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

/** The statements that make the session the CEO: the role and the claims PostgREST would set. */
export function asCeoSql(identity: CeoIdentity): string {
  assertUuid(identity.userId, 'the user id');
  assertUuid(identity.sessionId, 'the session id');
  const claims = JSON.stringify({
    sub: identity.userId,
    role: 'authenticated',
    aal: 'aal2',
    session_id: identity.sessionId,
  });
  return `SET LOCAL ROLE authenticated; SELECT set_config('request.jwt.claims', '${claims}', true);`;
}

/** The row lock both write functions take first: the process row, FOR NO KEY UPDATE (F-82). */
export function lockProcessSql(processId: string): string {
  assertUuid(processId, 'the process id');
  return `SELECT id FROM public.processes WHERE id = '${processId}' FOR NO KEY UPDATE;`;
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
  /** Takes the process row lock the way the write functions do, as the database owner. */
  lockProcess(processId: string): Promise<void>;
  /** Runs the REAL `update_process` that cancels the process; the transaction stays open. */
  cancelProcess(identity: CeoIdentity, processId: string): Promise<void>;
  /** Runs the REAL `approve_current_stage`; the transaction stays open. */
  approveStage(identity: CeoIdentity, processId: string, expectedStageId: string): Promise<void>;
  /** Commits, which releases every lock the transaction holds. */
  commit(): Promise<void>;
  /** Rolls back whatever is still open. Safe to call twice and after `commit`: put it in `finally`. */
  abort(): void;
};

/**
 * Opens the session and `BEGIN`s. Every method resolves once psql has run its statements, and rejects
 * if the session ended instead (a statement failed, or the stack is not running).
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

  let step = 0;
  /** Sends statements, then waits for psql to echo the sentinel that follows them. */
  async function run(statements: string): Promise<void> {
    if (ended) throw new Error('held transaction: the session is already over');
    step += 1;
    const sentinel = `${SENTINEL_PREFIX}${step}__`;
    child.stdin.write(`${statements}\n\\echo ${sentinel}\n`);

    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        watchers.delete(check);
        reject(new Error('held transaction: a step did not finish in time'));
      }, STEP_TIMEOUT_MS);
      const check = () => {
        if (output.includes(sentinel)) {
          clearTimeout(timer);
          watchers.delete(check);
          resolve();
        } else if (ended) {
          clearTimeout(timer);
          watchers.delete(check);
          reject(new Error('held transaction: the session ended: a statement failed'));
        }
      };
      watchers.add(check);
      check();
    });
  }

  await run(`SET idle_in_transaction_session_timeout = '${IDLE_IN_TRANSACTION_LIMIT}'; BEGIN;`);

  return {
    lockProcess: (processId) => run(lockProcessSql(processId)),
    cancelProcess: (identity, processId) => run(cancelProcessSql(identity, processId)),
    approveStage: (identity, processId, expectedStageId) =>
      run(approveStageSql(identity, processId, expectedStageId)),
    async commit() {
      await run('COMMIT;');
      child.stdin.end();
      await new Promise<void>((resolve, reject) => {
        const check = () => {
          if (!ended) return;
          watchers.delete(check);
          if (exitCode === 0) resolve();
          else reject(new Error('held transaction: the session did not end cleanly'));
        };
        watchers.add(check);
        check();
      });
    },
    abort() {
      if (ended) return;
      // End of input makes psql quit, which rolls back an open transaction; the kill is for a hung one.
      child.stdin.end();
      child.kill();
    },
  };
}

/**
 * Waits until at least `count` backends are blocked on a lock inside a statement that names `routine`:
 * the requests a test fired are parked, so they are simultaneous in the only sense that matters.
 * It polls the database (`countLockWaiters`) until that holds, with a bound: no fixed delay, and a
 * request that never reaches the lock fails the test with this message instead of hanging.
 */
export async function waitForLockWaiters(routine: string, count: number): Promise<void> {
  await vi.waitFor(
    async () => {
      const waiting = await countLockWaiters(routine);
      if (waiting < count) {
        throw new Error(`${waiting} of ${count} ${routine} calls are waiting for the lock`);
      }
    },
    { timeout: WAIT_FOR_WAITERS_TIMEOUT_MS, interval: WAIT_FOR_WAITERS_INTERVAL_MS },
  );
}
