import { describe, expect, it } from 'vitest';
import {
  approveStageSql,
  asCeoSql,
  cancelProcessSql,
  lockProcessSql,
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
    expect(() => cancelProcessSql(IDENTITY, bad)).toThrow(/not a UUID/);
    expect(() => approveStageSql(IDENTITY, bad, STAGE_ID)).toThrow(/not a UUID/);
    expect(() => approveStageSql(IDENTITY, PROCESS_ID, bad)).toThrow(/not a UUID/);
    expect(() => asCeoSql({ ...IDENTITY, userId: bad })).toThrow(/not a UUID/);
    expect(() => asCeoSql({ ...IDENTITY, sessionId: bad })).toThrow(/not a UUID/);
  });
});
