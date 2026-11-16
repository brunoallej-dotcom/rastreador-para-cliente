import { describe, expect, it } from 'vitest';
import {
  createProcessBodySchema,
  listClientProcessesQuerySchema,
  processIdParamsSchema,
  toProcessPatch,
  toStageInputs,
  updateProcessBodySchema,
} from './process.schema';

const PROCESS_ID = '00000000-0000-4000-8000-0000000001a1';
const LONE_SURROGATE = String.fromCharCode(0xd800);
const HANGUL_FILLER = String.fromCodePoint(0x3164);
const ZERO_WIDTH_SPACE = String.fromCodePoint(0x200b);

const stages = (count: number) =>
  Array.from({ length: count }, (_value, index) => ({ name: `Fase ${index + 1}` }));

describe('processIdParamsSchema', () => {
  it('accepts a UUID and rejects anything else (E-06)', () => {
    expect(processIdParamsSchema.safeParse({ processId: PROCESS_ID }).success).toBe(true);
    expect(processIdParamsSchema.safeParse({ processId: 'not-a-uuid' }).success).toBe(false);
    expect(processIdParamsSchema.safeParse({}).success).toBe(false);
  });

  it('is strict: another path param is refused', () => {
    expect(processIdParamsSchema.safeParse({ processId: PROCESS_ID, other: 'x' }).success).toBe(
      false,
    );
  });
});

describe('listClientProcessesQuerySchema', () => {
  it('defaults to 50 per page and no status filter', () => {
    expect(listClientProcessesQuerySchema.parse({})).toEqual({ limit: 50 });
  });

  it('parses limit, cursor and each of the three statuses', () => {
    expect(
      listClientProcessesQuerySchema.parse({ limit: '100', cursor: 'abc_-', status: 'active' }),
    ).toEqual({ limit: 100, cursor: 'abc_-', status: 'active' });
    for (const status of ['active', 'completed', 'cancelled']) {
      expect(listClientProcessesQuerySchema.parse({ status }).status).toBe(status);
    }
  });

  it.each([
    ['limit=0', { limit: '0' }],
    ['limit=101', { limit: '101' }],
    ['status=done', { status: 'done' }],
    ['status=ACTIVE', { status: 'ACTIVE' }],
    ['an empty status', { status: '' }],
    ['a repeated status', { status: ['active', 'completed'] }],
    ['an unknown parameter', { clientId: 'x' }],
  ])('refuses %s', (_label, query) => {
    expect(listClientProcessesQuerySchema.safeParse(query).success).toBe(false);
  });
});

describe('createProcessBodySchema', () => {
  it('AC-15: accepts a title alone (the template is used)', () => {
    expect(createProcessBodySchema.parse({ title: 'Site novo' })).toEqual({ title: 'Site novo' });
  });

  it('AC-15: accepts from 1 to 30 stages, with or without a description', () => {
    for (const count of [1, 30]) {
      expect(createProcessBodySchema.safeParse({ title: 'P', stages: stages(count) }).success).toBe(
        true,
      );
    }
    expect(
      createProcessBodySchema.parse({
        title: 'P',
        stages: [{ name: 'A', description: 'Detalhe' }, { name: 'B' }],
      }).stages,
    ).toEqual([{ name: 'A', description: 'Detalhe' }, { name: 'B' }]);
  });

  it('E-30: trims the title and the names and normalizes them to NFC', () => {
    const parsed = createProcessBodySchema.parse({
      title: `  Caf${'e'}${String.fromCodePoint(0x0301)}  `,
      stages: [{ name: '  Etapa  ' }],
    });

    expect(parsed.title).toBe(`Caf${String.fromCodePoint(0x00e9)}`);
    expect(parsed.stages?.[0]?.name).toBe('Etapa');
  });

  it.each([
    ['no title', {}],
    ['an empty title', { title: '' }],
    ['a title of spaces', { title: '   ' }],
    ['a title over 160 characters', { title: 'a'.repeat(161) }],
    ['a title with a newline', { title: 'Linha\ndupla' }],
    ['a title with a zero-width space', { title: `Zero${ZERO_WIDTH_SPACE}width` }],
    ['a title with a Hangul filler', { title: `a${HANGUL_FILLER}b` }],
    ['a title of only punctuation', { title: '***' }],
    ['a title with a lone surrogate', { title: `A${LONE_SURROGATE}` }],
    ['a title that is not text', { title: 42 }],
    ['an empty stage list', { title: 'P', stages: [] }],
    ['31 stages', { title: 'P', stages: stages(31) }],
    ['stages that are not a list', { title: 'P', stages: { name: 'A' } }],
    ['a stage with no name', { title: 'P', stages: [{}] }],
    ['a stage named with spaces only', { title: 'P', stages: [{ name: '   ' }] }],
    ['a stage name over 120 characters', { title: 'P', stages: [{ name: 'a'.repeat(121) }] }],
    ['a stage name with a control character', { title: 'P', stages: [{ name: 'a\tb' }] }],
    [
      'a description over 2000 characters',
      { title: 'P', stages: [{ name: 'A', description: 'd'.repeat(2001) }] },
    ],
    ['a description with a newline', { title: 'P', stages: [{ name: 'A', description: 'a\nb' }] }],
    ['a stage with a position or an id', { title: 'P', stages: [{ name: 'A', position: 1 }] }],
    ['a clientId in the body', { title: 'P', clientId: PROCESS_ID }],
    ['a status in the body', { title: 'P', status: 'completed' }],
    ['a null stages', { title: 'P', stages: null }],
  ])('E-20, AC-23: refuses %s', (_label, body) => {
    expect(createProcessBodySchema.safeParse(body).success).toBe(false);
  });

  it('E-20: points at the stage and the field that failed', () => {
    const result = createProcessBodySchema.safeParse({
      title: 'P',
      stages: [{ name: 'Boa' }, { name: '   ' }],
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.map((issue) => issue.path.join('.'))).toEqual(['stages.1.name']);
    }
  });

  it('accepts 120 characters in a stage name and 2000 in a description', () => {
    const result = createProcessBodySchema.safeParse({
      title: 'a'.repeat(160),
      stages: [{ name: 'n'.repeat(120), description: 'd'.repeat(2000) }],
    });

    expect(result.success).toBe(true);
  });
});

describe('toStageInputs', () => {
  it('turns a missing, empty or blank description into null and keeps a real one', () => {
    const parsed = createProcessBodySchema.parse({
      title: 'P',
      stages: [
        { name: 'A' },
        { name: 'B', description: '' },
        { name: 'C', description: '    ' },
        { name: 'D', description: ' Detalhe ' },
      ],
    });

    expect(toStageInputs(parsed.stages ?? [])).toEqual([
      { name: 'A', description: null },
      { name: 'B', description: null },
      { name: 'C', description: null },
      { name: 'D', description: 'Detalhe' },
    ]);
  });
});

describe('updateProcessBodySchema', () => {
  it('AC-19: accepts a title, a cancellation or both', () => {
    expect(updateProcessBodySchema.parse({ title: 'Novo' })).toEqual({ title: 'Novo' });
    expect(updateProcessBodySchema.parse({ status: 'cancelled' })).toEqual({ status: 'cancelled' });
    expect(updateProcessBodySchema.parse({ title: 'Novo', status: 'cancelled' })).toEqual({
      title: 'Novo',
      status: 'cancelled',
    });
  });

  it.each([
    ['an empty body', {}],
    ['a status that is not the one manual transition', { status: 'completed' }],
    ['an active status', { status: 'active' }],
    ['a null status', { status: null }],
    ['an empty title', { title: '' }],
    ['a title of spaces', { title: '  ' }],
    ['a title over 160 characters', { title: 'a'.repeat(161) }],
    ['a field the contract does not have', { title: 'Novo', version: 3 }],
    ['an id in the body', { id: PROCESS_ID, title: 'Novo' }],
  ])('AC-23: refuses %s', (_label, body) => {
    expect(updateProcessBodySchema.safeParse(body).success).toBe(false);
  });

  it('points an empty body at the body, not at a field', () => {
    const result = updateProcessBodySchema.safeParse({});

    expect(result.success).toBe(false);
    if (!result.success) expect(result.error.issues.map((issue) => issue.path)).toEqual([[]]);
  });
});

describe('toProcessPatch', () => {
  it('carries only the fields the body has, and `status: cancelled` becomes `cancel: true`', () => {
    expect(toProcessPatch({ title: 'Novo' })).toEqual({ title: 'Novo' });
    expect(toProcessPatch({ status: 'cancelled' })).toEqual({ cancel: true });
    expect(toProcessPatch({ title: 'Novo', status: 'cancelled' })).toEqual({
      title: 'Novo',
      cancel: true,
    });
  });
});
