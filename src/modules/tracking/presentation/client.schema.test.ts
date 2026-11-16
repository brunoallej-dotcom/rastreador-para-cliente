import { describe, expect, it } from 'vitest';
import {
  clientIdParamsSchema,
  createClientBodySchema,
  listClientsQuerySchema,
  updateClientBodySchema,
} from './client.schema';

const CLIENT_ID = '00000000-0000-4000-8000-00000000000a';

describe('clientIdParamsSchema', () => {
  it('accepts a UUID and rejects anything else (E-06)', () => {
    expect(clientIdParamsSchema.safeParse({ clientId: CLIENT_ID }).success).toBe(true);
    expect(clientIdParamsSchema.safeParse({ clientId: 'not-a-uuid' }).success).toBe(false);
    expect(clientIdParamsSchema.safeParse({}).success).toBe(false);
  });

  it('is strict: another path param is refused', () => {
    expect(clientIdParamsSchema.safeParse({ clientId: CLIENT_ID, other: 'x' }).success).toBe(false);
  });
});

describe('listClientsQuerySchema', () => {
  it('defaults to 50 per page and active clients only', () => {
    expect(listClientsQuerySchema.parse({})).toEqual({ limit: 50, includeArchived: false });
  });

  it('parses limit, cursor and includeArchived', () => {
    expect(
      listClientsQuerySchema.parse({ limit: '100', cursor: 'abc_-', includeArchived: 'true' }),
    ).toEqual({ limit: 100, cursor: 'abc_-', includeArchived: true });
    expect(listClientsQuerySchema.parse({ includeArchived: 'false' }).includeArchived).toBe(false);
  });

  it.each([
    ['limit=0', { limit: '0' }],
    ['limit=101', { limit: '101' }],
    ['limit=1e1', { limit: '1e1' }],
    ['includeArchived=yes', { includeArchived: 'yes' }],
    ['includeArchived=1', { includeArchived: '1' }],
    ['includeArchived=TRUE', { includeArchived: 'TRUE' }],
    ['a cursor outside the base64url alphabet', { cursor: 'a b' }],
    ['an unknown param', { clientId: CLIENT_ID }],
  ])('refuses %s', (_label, query) => {
    expect(listClientsQuerySchema.safeParse(query).success).toBe(false);
  });
});

describe('createClientBodySchema', () => {
  it('E-30: trims the name and normalizes it to NFC', () => {
    const composed = 'Caf\u00e9';
    const decomposed = 'Cafe\u0301';

    expect(createClientBodySchema.parse({ name: `  ${decomposed}  ` })).toEqual({ name: composed });
  });

  it('accepts 160 characters and refuses 161 (counted in code points)', () => {
    expect(createClientBodySchema.safeParse({ name: 'a'.repeat(160) }).success).toBe(true);
    expect(createClientBodySchema.safeParse({ name: 'a'.repeat(161) }).success).toBe(false);
    expect(createClientBodySchema.safeParse({ name: '\u{1F600}'.repeat(160) }).success).toBe(false);
  });

  it.each([
    ['empty', ''],
    ['only spaces', '   '],
    ['a line break', 'Linha\ndupla'],
    ['a zero-width space', 'Zero\u200Bwidth'],
    ['a bidi override', 'Bidi\u202Eoverride'],
    ['only symbols', '***'],
    ['a lone surrogate (F-54)', `A${String.fromCharCode(0xd800)}`],
    ['not a string', 42],
    ['null', null],
  ])('E-30: refuses a name that is %s', (_label, name) => {
    expect(createClientBodySchema.safeParse({ name }).success).toBe(false);
  });

  it('is strict: a clientId, an id or any other field is refused (mass assignment)', () => {
    expect(createClientBodySchema.safeParse({ name: 'Acme', clientId: CLIENT_ID }).success).toBe(
      false,
    );
    expect(createClientBodySchema.safeParse({ name: 'Acme', archivedAt: null }).success).toBe(
      false,
    );
    expect(createClientBodySchema.safeParse({}).success).toBe(false);
  });
});

describe('updateClientBodySchema', () => {
  it('accepts name, archived or both', () => {
    expect(updateClientBodySchema.parse({ name: ' Novo ' })).toEqual({ name: 'Novo' });
    expect(updateClientBodySchema.parse({ archived: false })).toEqual({ archived: false });
    expect(updateClientBodySchema.parse({ name: 'Novo', archived: true })).toEqual({
      name: 'Novo',
      archived: true,
    });
  });

  it('AC-11: an empty body is refused with the body as the path (minProperties: 1)', () => {
    const result = updateClientBodySchema.safeParse({});

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.map((issue) => issue.message)).toEqual([
        'Must name at least one field to change',
      ]);
      expect(result.error.issues.map((issue) => issue.path)).toEqual([[]]);
    }
  });

  it.each([
    ['a bad name', { name: '' }],
    ['a non-boolean archived', { archived: 'true' }],
    ['null for archived', { archived: null }],
    ['a clientId', { name: 'Acme', clientId: CLIENT_ID }],
    ['an unknown field', { name: 'Acme', color: 'red' }],
  ])('refuses %s', (_label, body) => {
    expect(updateClientBodySchema.safeParse(body).success).toBe(false);
  });
});
