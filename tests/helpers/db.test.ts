import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { dbContainerName, parseProjectId, parseRowsOutput } from './db';

describe('parseRowsOutput (what psql prints inside the db container)', () => {
  it('reads one JSON array of rows, however it is wrapped over lines', () => {
    const output = JSON.stringify([{ user_id: 'u1' }, { user_id: 'u2' }], null, 2);

    expect(parseRowsOutput(output)).toEqual([{ user_id: 'u1' }, { user_id: 'u2' }]);
    expect(parseRowsOutput('[{"n": 1}, \n {"n": 2}]\n')).toEqual([{ n: 1 }, { n: 2 }]);
  });

  it('reads an empty result', () => {
    expect(parseRowsOutput('[]\n')).toEqual([]);
  });

  it.each([
    ['no output', ''],
    ['blank output', '  \n'],
    ['text only', 'UPDATE 1'],
    ['an object (the shape the CLI prints in agent mode)', '{"rows": [{"n": 1}]}'],
    ['an array of scalars', '[1, 2]'],
    ['an array with an array in it', '[[1]]'],
    ['two arrays', '[] []'],
    ['broken JSON', '[{"n": 1'],
  ])('fails loudly on %s (a helper that guessed would test nothing)', (_label, output) => {
    expect(() => parseRowsOutput(output)).toThrow(/not a JSON array of rows/);
  });
});

describe('the name of the db container (it depends on nothing but the db container)', () => {
  it('is supabase_db_<project_id> of the config.toml of this repository', () => {
    const toml = readFileSync(
      fileURLToPath(new URL('../../supabase/config.toml', import.meta.url)),
      'utf8',
    );

    expect(dbContainerName()).toBe(dbContainerName(toml));
    expect(dbContainerName()).toMatch(/^supabase_db_[A-Za-z0-9][A-Za-z0-9_.-]*$/);
  });

  it('reads the project id from a TOML line', () => {
    expect(parseProjectId('# comment\nproject_id = "my-project"\n[api]\nport = 1\n')).toBe(
      'my-project',
    );
    expect(dbContainerName('project_id = "x_y.z-1"')).toBe('supabase_db_x_y.z-1');
  });

  it.each([
    ['no project_id', '[api]\nport = 1\n'],
    ['an empty project_id', 'project_id = ""\n'],
    ['a project_id with a space', 'project_id = "a b"\n'],
    ['a project_id that could become an option', 'project_id = "-v"\n'],
    ['a commented-out project_id', '# project_id = "x"\n'],
  ])('refuses %s', (_label, toml) => {
    expect(() => parseProjectId(toml)).toThrow(/no usable project_id/);
  });
});
