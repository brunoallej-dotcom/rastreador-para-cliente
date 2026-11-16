// The tracking fixtures of `db.ts` (Wave 10) build SQL text out of their arguments, so they refuse
// anything but a UUID, one strict timestamp shape, a small whole number or a plain label BEFORE the
// statement is built, and so before docker is touched. These tests need no database.
import { describe, expect, it } from 'vitest';
import {
  approveCurrentStageAsFixture,
  insertProcessesAtFixture,
  insertProcessWithoutStagesFixture,
} from './db';

const UUID = '00000000-0000-4000-8000-0000000001a1';
const INJECTION = `${UUID}'; DROP TABLE public.processes; --`;
const INSTANT = '2026-03-03T10:00:00.123456+00:00';

describe('approveCurrentStageAsFixture', () => {
  it('refuses a process or an approver that is not a UUID', async () => {
    await expect(approveCurrentStageAsFixture('nope', UUID)).rejects.toThrow(/not a UUID/);
    await expect(approveCurrentStageAsFixture(UUID, INJECTION)).rejects.toThrow(/not a UUID/);
    await expect(approveCurrentStageAsFixture(INJECTION, UUID)).rejects.toThrow(/not a UUID/);
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
});

describe('insertProcessWithoutStagesFixture', () => {
  it('refuses a client that is not a UUID and a label that is not plain text', async () => {
    await expect(insertProcessWithoutStagesFixture('nope', 'Vazio')).rejects.toThrow(/not a UUID/);
    await expect(insertProcessWithoutStagesFixture(UUID, "x'); --")).rejects.toThrow(
      /not plain text/,
    );
  });
});
