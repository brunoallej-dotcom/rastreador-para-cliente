// The tracking fixtures of `db.ts` (Wave 10) build SQL text out of their arguments and run it as a
// superuser, so they refuse anything but a UUID, one strict timestamp shape, a small whole number or a
// plain label BEFORE the statement is built, and so before docker is touched. Each fixture is ONE
// statement (it commits whole or not at all), and no value the database returns is put back into SQL.
// These tests need no database.
import { describe, expect, it } from 'vitest';
import {
  approveCurrentStageAsFixture,
  approveCurrentStageSql,
  archiveClientFixture,
  archiveClientSql,
  countClientsNamed,
  countProcessesOf,
  deleteProcessFixture,
  deleteProcessSql,
  fixtureReasonOf,
  insertClientFixture,
  insertClientsFixture,
  insertClientsSql,
  insertProcessesAtFixture,
  insertProcessesAtSql,
  insertProcessWithoutStagesFixture,
  readClientRow,
  readProcessRow,
  readStageRows,
  seedProcessesFixture,
  seedProcessesSql,
  textLiteral,
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

// ------------------------------------------------ Wave 10.1: the fixtures that replaced the secret key ----

describe('textLiteral (a text that goes into SQL as the hex of its UTF-8 bytes)', () => {
  it('shows nothing but hex digits between the quotes, whatever the text holds', () => {
    for (const text of [
      "O'Brien",
      "x'); DROP TABLE public.clients; --",
      'a\\b',
      '$$ $fixture$',
      `caf${String.fromCodePoint(0xe9)}`,
      String.fromCodePoint(0x00a0, 0x3000, 0xfeff),
      '\n\t',
    ]) {
      const sql = textLiteral(text, 'test');

      expect(literalsOf(sql)).toEqual([Buffer.from(text, 'utf8').toString('hex'), 'hex', 'UTF8']);
      expect(literalsOf(sql)[0]).toMatch(/^[0-9a-f]+$/);
      expect(sql.startsWith("convert_from(decode('")).toBe(true);
    }
  });

  it('refuses an empty text and one over 16 KiB, before anything is built', () => {
    expect(() => textLiteral('', 'test')).toThrow(/empty or too long/);
    expect(() => textLiteral('a'.repeat(16 * 1024 + 1), 'test')).toThrow(/empty or too long/);
    expect(textLiteral('a'.repeat(16 * 1024), 'test')).toContain('convert_from');
  });
});

describe('insertClientsFixture', () => {
  it('refuses a count outside 1 to 50 and an instant that is not one strict shape', async () => {
    await expect(insertClientsFixture([])).rejects.toThrow(/whole number from 1 to 50/);
    await expect(
      insertClientsFixture(Array.from({ length: 51 }, (_v, i) => `Cliente ${i}`)),
    ).rejects.toThrow(/whole number from 1 to 50/);
    await expect(insertClientsFixture(['Cliente'], "2026-03-03'; --")).rejects.toThrow(
      /not an ISO timestamp/,
    );
    await expect(insertClientFixture('')).rejects.toThrow(/empty or too long/);
  });

  it('is ONE multi-row INSERT: the same creation instant for all of them, unless one is given', () => {
    const rows = [
      { id: UUID, name: 'Um' },
      { id: OTHER_UUID, name: 'Dois' },
    ];

    const plain = insertClientsSql(rows);
    const dated = insertClientsSql(rows, INSTANT);

    expect(plain.startsWith('INSERT INTO public.clients (id, name) VALUES (')).toBe(true);
    expect(plain).not.toContain(';');
    expect(plain).toContain(`'${UUID}'`);
    expect(dated.startsWith('INSERT INTO public.clients (id, name, created_at, updated_at)')).toBe(
      true,
    );
    expect(dated.match(new RegExp(INSTANT.replaceAll('+', '\\+'), 'g'))).toHaveLength(4);
  });

  it('refuses an id that is not a UUID and keeps the name out of the SQL text as such', () => {
    expect(() => insertClientsSql([{ id: INJECTION, name: 'Um' }])).toThrow(/not a UUID/);
    const sql = insertClientsSql([{ id: UUID, name: "x'; DROP TABLE public.clients; --" }]);

    expect(sql).not.toContain('DROP TABLE');
    expect(sql).toContain(Buffer.from("x'; DROP TABLE public.clients; --", 'utf8').toString('hex'));
  });
});

describe('archiveClientFixture, readClientRow, countClientsNamed', () => {
  it('refuse an id that is not a UUID, before docker is touched', async () => {
    await expect(archiveClientFixture(INJECTION)).rejects.toThrow(/not a UUID/);
    await expect(readClientRow('nope')).rejects.toThrow(/not a UUID/);
    await expect(countClientsNamed('')).rejects.toThrow(/empty or too long/);
  });

  it('archiving is one UPDATE of one client, by id', () => {
    expect(archiveClientSql(UUID)).toBe(
      `UPDATE public.clients SET archived_at = now() WHERE id = '${UUID}' RETURNING id`,
    );
  });
});

describe('seedProcessesFixture', () => {
  const ids = {
    active: [UUID],
    completed: [OTHER_UUID],
    cancelled: ['00000000-0000-4000-8000-0000000001c3'],
  } as const;

  it('refuses a completed process with no CEO to approve it, and ids that are not UUIDs', async () => {
    await expect(seedProcessesFixture(UUID, { completed: 1 })).rejects.toThrow(
      /needs the CEO who approved it/,
    );
    await expect(seedProcessesFixture(INJECTION, { active: 1 })).rejects.toThrow(/not a UUID/);
    await expect(seedProcessesFixture(UUID, { active: 1 }, INJECTION)).rejects.toThrow(
      /not a UUID/,
    );
    await expect(seedProcessesFixture(UUID, { active: 51 })).rejects.toThrow(
      /whole number from 1 to 50/,
    );
  });

  it('writes nothing when there is nothing to seed', async () => {
    await expect(seedProcessesFixture(UUID, {})).resolves.toBeUndefined();
    await expect(seedProcessesFixture(UUID, { active: 0, completed: 0 })).resolves.toBeUndefined();
  });

  it('is ONE statement that gives every process the stage its state needs (I1 to I5)', () => {
    const sql = seedProcessesSql(UUID, ids, OTHER_UUID);

    expect(sql.startsWith('WITH p AS (')).toBe(true);
    expect(sql).not.toContain(';');
    // one stage each: in progress for active and cancelled, completed (with the approval) for completed
    expect(sql).toContain("CASE WHEN status = 'completed' THEN 'completed' ELSE 'in_progress' END");
    expect(sql).toContain("'active'::public.process_status, NULL::timestamptz, NULL::timestamptz");
    expect(sql).toContain("'completed'::public.process_status, now(), NULL::timestamptz");
    expect(sql).toContain("'cancelled'::public.process_status, NULL::timestamptz, now()");
    expect(sql).toContain('INSERT INTO public.stage_approvals');
    expect(sql).toContain(`SELECT s.id, s.process_id, '${OTHER_UUID}'::uuid`);
  });

  it('writes no approver when nobody completed, and refuses an empty seed', () => {
    const none = { active: [UUID], completed: [], cancelled: [] } as const;

    expect(seedProcessesSql(UUID, none, undefined)).toContain(
      'SELECT s.id, s.process_id, NULL::uuid',
    );
    expect(() =>
      seedProcessesSql(UUID, { active: [], completed: [], cancelled: [] }, undefined),
    ).toThrow(/no process to insert/);
  });

  it('puts only UUIDs and hex into the text', () => {
    const sql = seedProcessesSql(UUID, ids, OTHER_UUID);
    const literals = literalsOf(sql).filter((literal) => literal !== undefined);

    for (const literal of literals) {
      expect(literal).toMatch(
        /^([0-9a-f-]{36}|[0-9a-f]+|hex|UTF8|active|completed|cancelled|Unica|in_progress)$/,
      );
    }
  });
});

describe('the reads of the tracking tables', () => {
  it('refuse an id that is not a UUID, before docker is touched', async () => {
    await expect(countProcessesOf(INJECTION)).rejects.toThrow(/not a UUID/);
    await expect(readProcessRow('nope')).rejects.toThrow(/not a UUID/);
    await expect(readStageRows(`${UUID} OR true`)).rejects.toThrow(/not a UUID/);
  });
});
