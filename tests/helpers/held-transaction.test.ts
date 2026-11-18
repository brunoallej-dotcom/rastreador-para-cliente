import { describe, expect, it } from 'vitest';
import {
  approveStageSql,
  archiveClientSql,
  asCeoSql,
  cancelProcessSql,
  createProcessSql,
  lockProcessSql,
  lockStageSql,
  OPEN_TRANSACTION_SQL,
  parseBackendPid,
  renameProcessSql,
  REPORT_PID_SQL,
  type CeoIdentity,
} from './held-transaction';

const IDENTITY: CeoIdentity = {
  userId: '11111111-1111-4111-8111-111111111111',
  sessionId: '22222222-2222-4222-8222-222222222222',
};
const PROCESS_ID = '44444444-4444-4444-8444-444444444444';
const STAGE_ID = '55555555-5555-4555-8555-555555555555';

describe('the statements of a held transaction (what a test sends to the database)', () => {
  it('lockProcessSql takes the lock the write functions take: the process row, FOR NO KEY UPDATE', () => {
    expect(lockProcessSql(PROCESS_ID)).toBe(
      `SELECT id FROM public.processes WHERE id = '${PROCESS_ID}' FOR NO KEY UPDATE;`,
    );
  });

  it('lockStageSql takes ONLY the stage row, FOR NO KEY UPDATE: the lock an approval takes second', () => {
    const sql = lockStageSql(STAGE_ID);

    expect(sql).toBe(
      `SELECT id FROM public.process_stages WHERE id = '${STAGE_ID}' FOR NO KEY UPDATE;`,
    );
    expect(sql).not.toContain('public.processes');
  });

  it('asCeoSql becomes the attested CEO: the authenticated role and the claims PostgREST would set', () => {
    const sql = asCeoSql(IDENTITY);

    expect(sql).toContain('SET LOCAL ROLE authenticated;');
    const claims = /set_config\('request\.jwt\.claims', '([^']+)', true\)/.exec(sql)?.[1];
    expect(JSON.parse(claims ?? 'null')).toEqual({
      sub: IDENTITY.userId,
      role: 'authenticated',
      aal: 'aal2',
      session_id: IDENTITY.sessionId,
    });
  });

  it('asCeoSql also sets the request id header, so the audit rows it writes carry a request_id like the API ones', () => {
    const sql = asCeoSql(IDENTITY);

    const headers = /set_config\('request\.headers', '([^']+)', true\)/.exec(sql)?.[1];
    const requestId = (JSON.parse(headers ?? 'null') as Record<string, string>)['x-request-id'];
    expect(requestId).toBeDefined();
    // the same shape the audit table accepts (`audit_events.request_id` CHECK)
    expect(requestId).toMatch(/^[A-Za-z0-9-]{1,64}$/);
  });

  it('cancelProcessSql and approveStageSql call the REAL functions, as the CEO, and give the role back', () => {
    const cancel = cancelProcessSql(IDENTITY, PROCESS_ID);
    const approve = approveStageSql(IDENTITY, PROCESS_ID, STAGE_ID);

    expect(cancel).toContain(`public.update_process('${PROCESS_ID}', NULL, true)`);
    expect(approve).toContain(`public.approve_current_stage('${PROCESS_ID}', '${STAGE_ID}')`);
    for (const sql of [cancel, approve]) {
      expect(sql.startsWith(asCeoSql(IDENTITY))).toBe(true);
      expect(sql.endsWith('RESET ROLE;')).toBe(true);
    }
  });

  it.each([
    ['an empty id', ''],
    ['a quote', `${PROCESS_ID}'`],
    ['a statement after the id', `${PROCESS_ID}'; DROP TABLE public.processes; --`],
    ['text that is not a UUID', 'not-a-uuid'],
    ['a UUID with a trailing space', `${PROCESS_ID} `],
  ])('refuses %s anywhere an id reaches the SQL text', (_label, bad) => {
    expect(() => lockProcessSql(bad)).toThrow(/not a UUID/);
    expect(() => lockStageSql(bad)).toThrow(/not a UUID/);
    expect(() => cancelProcessSql(IDENTITY, bad)).toThrow(/not a UUID/);
    expect(() => approveStageSql(IDENTITY, bad, STAGE_ID)).toThrow(/not a UUID/);
    expect(() => approveStageSql(IDENTITY, PROCESS_ID, bad)).toThrow(/not a UUID/);
    expect(() => asCeoSql({ ...IDENTITY, userId: bad })).toThrow(/not a UUID/);
    expect(() => asCeoSql({ ...IDENTITY, sessionId: bad })).toThrow(/not a UUID/);
  });
});

describe('the statements of Wave 10.2 (F-80, F-87): archive, create and rename as the CEO', () => {
  it('archiveClientSql calls the REAL update_client with archived = true, as the CEO, and gives the role back', () => {
    const sql = archiveClientSql(IDENTITY, PROCESS_ID);

    expect(sql.startsWith(asCeoSql(IDENTITY))).toBe(true);
    expect(sql).toContain(`public.update_client('${PROCESS_ID}', NULL, true)`);
    expect(sql.trimEnd().endsWith('RESET ROLE;')).toBe(true);
  });

  it('createProcessSql and renameProcessSql call the REAL functions with the title as a plain literal', () => {
    expect(createProcessSql(IDENTITY, PROCESS_ID, 'Site novo')).toContain(
      `public.create_process('${PROCESS_ID}', 'Site novo')`,
    );
    expect(renameProcessSql(IDENTITY, PROCESS_ID, 'Site novo')).toContain(
      `public.update_process('${PROCESS_ID}', 'Site novo', NULL)`,
    );
  });

  it('refuses an id that is not a UUID and a title that needs escaping, before any SQL is built', () => {
    expect(() => archiveClientSql(IDENTITY, "x'; DROP TABLE public.clients; --")).toThrow(
      /not a UUID/,
    );
    expect(() => createProcessSql(IDENTITY, PROCESS_ID, "O'Brien")).toThrow(/title/);
    expect(() => renameProcessSql(IDENTITY, PROCESS_ID, '')).toThrow(/title/);
    expect(() => renameProcessSql(IDENTITY, 'not-a-uuid', 'Site')).toThrow(/not a UUID/);
  });
});

describe('the limits of a held session (F-108: it never outlives its test)', () => {
  const seconds = (limit: string) =>
    Number(new RegExp(`${limit} = '(\\d+)s'`).exec(OPEN_TRANSACTION_SQL)?.[1]);

  it('sets a lock timeout, a statement timeout and an idle-in-transaction timeout, all below the 30 s test timeout', () => {
    for (const limit of [
      'lock_timeout',
      'statement_timeout',
      'idle_in_transaction_session_timeout',
    ]) {
      const value = seconds(limit);
      expect(Number.isFinite(value), limit).toBe(true);
      expect(value, limit).toBeGreaterThan(0);
      expect(value, limit).toBeLessThan(30);
    }
    // the database rolls an abandoned transaction back before vitest gives up on the test
    expect(seconds('idle_in_transaction_session_timeout')).toBeLessThan(30);
    expect(seconds('lock_timeout')).toBeLessThanOrEqual(seconds('statement_timeout'));
  });

  it('applies the limits before the transaction begins, so none of them is lost to a rollback', () => {
    expect(OPEN_TRANSACTION_SQL.indexOf('lock_timeout')).toBeLessThan(
      OPEN_TRANSACTION_SQL.indexOf('BEGIN;'),
    );
    expect(OPEN_TRANSACTION_SQL.endsWith('BEGIN;')).toBe(true);
    expect(OPEN_TRANSACTION_SQL).not.toContain('SET LOCAL');
  });

  it('reports the backend pid first, with the statement a test can recognize in the output', () => {
    expect(REPORT_PID_SQL).toBe("SELECT 'held_backend_pid=' || pg_backend_pid();");
  });
});

describe('parseBackendPid (what the cleanup trusts to end a session)', () => {
  it('reads the pid the session printed, whatever else psql printed around it', () => {
    expect(parseBackendPid('held_backend_pid=4242\n__held_transaction_step_1__\n')).toBe(4242);
    expect(parseBackendPid('noise\nheld_backend_pid=7\n')).toBe(7);
  });

  it.each([
    ['no output', ''],
    ['no marker', '4242\n'],
    ['a marker with no number', 'held_backend_pid=\n'],
    ['a marker with text', 'held_backend_pid=abc\n'],
    ['a zero pid', 'held_backend_pid=0\n'],
    ['a pid beyond what a number holds exactly', `held_backend_pid=${'9'.repeat(20)}\n`],
  ])(
    'fails on %s: a cleanup that guessed a pid could end the wrong backend, or none',
    (_label, output) => {
      expect(() => parseBackendPid(output)).toThrow(/did not report its backend pid/);
    },
  );
});
