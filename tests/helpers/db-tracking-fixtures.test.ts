// The tracking fixtures of `db.ts` (Wave 10) build SQL text out of their arguments and run it as a
// superuser, so they refuse anything but a UUID, one strict timestamp shape, a small whole number or a
// plain label BEFORE the statement is built, and so before docker is touched. Each fixture is ONE
// statement (it commits whole or not at all), and no value the database returns is put back into SQL.
// These tests need no database.
import { describe, expect, it } from 'vitest';
import {
  approveCurrentStageAsFixture,
  approveCurrentStageSql,
  deleteProcessFixture,
  deleteProcessSql,
  fixtureReasonOf,
  insertProcessesAtFixture,
  insertProcessesAtSql,
  insertProcessWithoutStagesFixture,
} from './db';

const UUID = '00000000-0000-4000-8000-0000000001a1';
const OTHER_UUID = '00000000-0000-4000-8000-0000000001b2';
const INJECTION = `${UUID}'; DROP TABLE public.processes; --`;
const INSTANT = '2026-03-03T10:00:00.123456+00:00';

/** Every single-quoted literal of a statement, in order. */
const literalsOf = (sql: string) => [...sql.matchAll(/'([^']*)'/g)].map((match) => match[1]);

describe('approveCurrentStageAsFixture', () => {
  it('refuses a process or an approver that is not a UUID', async () => {
    await expect(approveCurrentStageAsFixture('nope', UUID)).rejects.toThrow(/not a UUID/);
    await expect(approveCurrentStageAsFixture(UUID, INJECTION)).rejects.toThrow(/not a UUID/);
    await expect(approveCurrentStageAsFixture(INJECTION, UUID)).rejects.toThrow(/not a UUID/);
  });

  it('is ONE statement: a single DO block, so the whole "Ok" commits or none of it does', () => {
    const sql = approveCurrentStageSql(UUID, OTHER_UUID);

    expect(sql.startsWith('DO $fixture$')).toBe(true);
    expect(sql.trimEnd().endsWith('$fixture$')).toBe(true);
    // the only `;` are the ones inside the PL/pgSQL body, none after the closing quote
    expect(sql.trimEnd().split('$fixture$')).toHaveLength(3);
  });

  it('guards that the process is active, locks it as the real function does, and refuses a stage that is not there', () => {
    const sql = approveCurrentStageSql(UUID, OTHER_UUID);

    expect(sql).toContain(`WHERE id = '${UUID}' AND status = 'active' FOR NO KEY UPDATE`);
    expect(sql).toContain("RAISE EXCEPTION 'fixture: the process is not active'");
    expect(sql).toContain("RAISE EXCEPTION 'fixture: the process has no stage in progress'");
    // the guard comes before the first write
    expect(sql.indexOf('FOR NO KEY UPDATE')).toBeLessThan(
      sql.indexOf('UPDATE public.process_stages'),
    );
    expect(sql.indexOf('UPDATE public.process_stages')).toBeLessThan(
      sql.indexOf('INSERT INTO public.stage_approvals'),
    );
  });

  it('puts nothing but the two ids it was given into the text: what the database returns stays in the database', () => {
    const sql = approveCurrentStageSql(UUID, OTHER_UUID);

    const literals = literalsOf(sql).filter((literal) => /^[0-9a-f-]{36}$/.test(literal ?? ''));
    expect(new Set(literals)).toEqual(new Set([UUID, OTHER_UUID]));
    // the stage id and its position are PL/pgSQL variables, never text
    expect(sql).toContain('VALUES (v_stage_id,');
    expect(sql).toContain('position = v_position + 1');
  });
});

describe('insertProcessesAtFixture', () => {
  it('refuses a client that is not a UUID', async () => {
    await expect(insertProcessesAtFixture(INJECTION, INSTANT, 2, 'Empate')).rejects.toThrow(
      /not a UUID/,
    );
  });

  it.each([
    ['text', 'yesterday'],
    ['a date only', '2026-03-03'],
    ['no offset', '2026-03-03T10:00:00'],
    ['a quote', `${INSTANT}'`],
    ['a statement', `${INSTANT}'; DROP TABLE public.processes; --`],
    ['more than six fraction digits', '2026-03-03T10:00:00.1234567+00:00'],
  ])('refuses an instant that is %s', async (_label, instant) => {
    await expect(insertProcessesAtFixture(UUID, instant, 2, 'Empate')).rejects.toThrow(
      /not an ISO timestamp/,
    );
  });

  it.each([0, -1, 1.5, 51, Number.NaN])('refuses a count of %s', async (count) => {
    await expect(insertProcessesAtFixture(UUID, INSTANT, count, 'Empate')).rejects.toThrow(
      /whole number from 1 to 50/,
    );
  });

  it.each(["O'Brien", 'a;b', '', 'x'.repeat(41), 'acentuação', '--'])(
    'refuses the label %j',
    async (label) => {
      await expect(insertProcessesAtFixture(UUID, INSTANT, 2, label)).rejects.toThrow(
        /not plain text/,
      );
    },
  );

  it('is ONE statement: the processes and their stages are a single data-modifying CTE', () => {
    const sql = insertProcessesAtSql(UUID, INSTANT, 'Empate', [OTHER_UUID, UUID]);

    expect(sql.startsWith('WITH p AS (INSERT INTO public.processes')).toBe(true);
    expect(sql).toContain('INSERT INTO public.process_stages');
    expect(sql).not.toContain(';');
    expect(sql).toContain(`ARRAY['${OTHER_UUID}', '${UUID}']::uuid[]`);
    expect(sql).toContain("'Empate ' || t.n");
  });

  it('refuses an id of its own list that is not a UUID, before anything is built', () => {
    expect(() => insertProcessesAtSql(UUID, INSTANT, 'Empate', [UUID, INJECTION])).toThrow(
      /not a UUID/,
    );
    expect(() => insertProcessesAtSql(UUID, INSTANT, "x'--", [UUID])).toThrow(/not plain text/);
    expect(() => insertProcessesAtSql(UUID, 'yesterday', 'Empate', [UUID])).toThrow(
      /not an ISO timestamp/,
    );
  });
});

describe('insertProcessWithoutStagesFixture', () => {
  it('refuses a client that is not a UUID and a label that is not plain text', async () => {
    await expect(insertProcessWithoutStagesFixture('nope', 'Vazio')).rejects.toThrow(/not a UUID/);
    await expect(insertProcessWithoutStagesFixture(UUID, "x'); --")).rejects.toThrow(
      /not plain text/,
    );
  });
});

describe('deleteProcessFixture', () => {
  it('refuses an id that is not a UUID, before docker is touched', async () => {
    await expect(deleteProcessFixture('nope')).rejects.toThrow(/not a UUID/);
    await expect(deleteProcessFixture(INJECTION)).rejects.toThrow(/not a UUID/);
    await expect(deleteProcessFixture(`${UUID} OR true`)).rejects.toThrow(/not a UUID/);
  });

  it('is one DELETE of one process, by id', () => {
    expect(deleteProcessSql(UUID)).toBe(
      `DELETE FROM public.processes WHERE id = '${UUID}' RETURNING id`,
    );
    expect(() => deleteProcessSql('')).toThrow(/not a UUID/);
  });
});

describe('fixtureReasonOf (the one sentence of psql that may be shown)', () => {
  it('reads the reason a fixture raised itself', () => {
    const stderr =
      'ERROR:  fixture: the process is not active\nCONTEXT:  PL/pgSQL function inline_code_block line 6 at RAISE\n';

    expect(fixtureReasonOf({ stderr })).toBe('the process is not active');
  });

  it('reads nothing from any other psql message, which can carry the statement or the row', () => {
    expect(
      fixtureReasonOf({ stderr: 'ERROR:  permission denied for table processes' }),
    ).toBeUndefined();
    expect(
      fixtureReasonOf({
        stderr:
          'ERROR:  duplicate key value violates unique constraint "x"\nDETAIL: (Processo secreto)',
      }),
    ).toBeUndefined();
    expect(fixtureReasonOf({ stderr: '' })).toBeUndefined();
  });

  it('reads nothing from something that is not an error with a text stderr', () => {
    for (const value of [undefined, null, 'fixture: x', 42, {}, { stderr: 7 }, { stderr: null }]) {
      expect(fixtureReasonOf(value)).toBeUndefined();
    }
  });

  it('shows at most the plain words of a reason, never data after them', () => {
    const stderr = "ERROR:  fixture: the process is not active (title 'Processo secreto')";

    expect(fixtureReasonOf({ stderr })).toBe('the process is not active');
    expect(fixtureReasonOf({ stderr })).not.toContain('secreto');
  });
});
