import { describe, expect, it } from 'vitest';
import { parseQueryOutput } from './db';

const answer = { boundary: 'abc', rows: [{ user_id: 'u1' }], warning: 'untrusted data' };

describe('parseQueryOutput (the CLI output of tests/helpers/db.ts)', () => {
  it('reads the bare JSON answer', () => {
    expect(parseQueryOutput(JSON.stringify(answer, null, 2)).rows).toEqual([{ user_id: 'u1' }]);
  });

  it('skips the progress lines before it and the update notice after it', () => {
    const output = [
      'Connecting to local database...',
      JSON.stringify(answer, null, 2),
      'A new version of Supabase CLI is available: v9.9.9',
    ].join('\n');

    expect(parseQueryOutput(output).rows).toEqual([{ user_id: 'u1' }]);
  });

  it('skips a line that opens an object but is not the answer', () => {
    const output = ['{ not json', JSON.stringify(answer, null, 2)].join('\n');

    expect(parseQueryOutput(output).rows).toHaveLength(1);
  });

  it('reads an empty result', () => {
    expect(parseQueryOutput(JSON.stringify({ ...answer, rows: [] })).rows).toEqual([]);
  });

  it.each([
    ['no output', ''],
    ['an object without rows', JSON.stringify({ boundary: 'x' })],
    ['rows that are not a list', JSON.stringify({ rows: 'x' })],
    ['rows that are not objects', JSON.stringify({ rows: [1, 2] })],
    ['text only', 'Connecting to local database...'],
  ])('fails loudly on %s (a helper that guessed would test nothing)', (_label, output) => {
    expect(() => parseQueryOutput(output)).toThrow(/no answer with rows/);
  });
});
