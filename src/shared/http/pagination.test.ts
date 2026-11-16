import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { ValidationError } from '@/shared/kernel';
import {
  CURSOR_MAX_LENGTH,
  decodeCursor,
  encodeCursor,
  pageQuerySchema,
  pageQueryShape,
} from './pagination';

const KIND = 'admin-clients';
const keyset = z.object({ createdAt: z.iso.datetime(), id: z.uuid() }).strict();
const position = {
  createdAt: '2026-11-15T12:00:00.000Z',
  id: '6f1d5a3e-3b0c-4f43-9a55-0d3f6f6f1a11',
};

function expectInvalid(result: ReturnType<typeof decodeCursor>) {
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(result.error).toBeInstanceOf(ValidationError);
  expect(result.error.code).toBe('VALIDATION_ERROR');
  expect(result.error.issues).toEqual([{ path: 'query.cursor', message: 'Invalid cursor' }]);
}

const toCursor = (envelope: string) => Buffer.from(envelope).toString('base64url');

const tamper = (cursor: string, patch: (json: string) => string) =>
  toCursor(patch(Buffer.from(cursor, 'base64url').toString('utf8')));

describe('cursor codec', () => {
  it('round-trips a position', () => {
    const cursor = encodeCursor(KIND, position);
    expect(cursor).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(cursor.length).toBeLessThanOrEqual(CURSOR_MAX_LENGTH);
    expect(decodeCursor(cursor, KIND, keyset)).toEqual({ ok: true, value: position });
  });

  it('is opaque: the cursor is not the readable position', () => {
    const cursor = encodeCursor(KIND, position);
    expect(cursor).not.toContain(position.id);
    expect(cursor).not.toContain('createdAt');
  });

  it.each([
    ['an empty string', ''],
    ['plain text', 'not a cursor'],
    ['characters outside base64url', 'abc+/=def'],
    ['valid base64url that is not JSON', toCursor('hello world')],
    ['JSON that is not an envelope', toCursor('{"a":1}')],
    ['an envelope of another version', toCursor(`{"v":2,"k":"${KIND}","p":{}}`)],
    ['an envelope with extra keys', toCursor(`{"v":1,"k":"${KIND}","p":{},"x":1}`)],
    ['an envelope without a kind', toCursor('{"v":1,"p":{}}')],
    ['a JSON array', toCursor('[1,2,3]')],
    ['invalid UTF-8', Buffer.from([0x7b, 0xff, 0xfe, 0x7d]).toString('base64url')],
    ['a cursor above the maximum length', 'a'.repeat(CURSOR_MAX_LENGTH + 1)],
  ])('rejects %s with a ValidationError (E-29)', (_name, cursor) => {
    expectInvalid(decodeCursor(cursor, KIND, keyset));
  });

  it('rejects a cursor whose payload was edited', () => {
    const cursor = encodeCursor(KIND, position);
    for (const patch of [
      (json: string) => json.replace('2026', 'xxxx'),
      (json: string) => json.replace('"id"', '"uid"'),
      (json: string) => json.replace('}}', ',"extra":1}}'),
    ]) {
      expectInvalid(decodeCursor(tamper(cursor, patch), KIND, keyset));
    }
  });

  it('rejects a truncated cursor and one with a flipped character', () => {
    const cursor = encodeCursor(KIND, position);
    expectInvalid(decodeCursor(cursor.slice(0, -4), KIND, keyset));
    expectInvalid(decodeCursor(`${cursor.slice(0, 10)}!${cursor.slice(11)}`, KIND, keyset));
  });

  it('rejects a non-canonical re-encoding of the same bytes', () => {
    const cursor = encodeCursor(KIND, { n: 1 });
    expectInvalid(decodeCursor(`${cursor}=`, KIND, z.object({ n: z.number() }).strict()));
  });

  it('rejects a cursor minted for another endpoint kind, even with a payload that fits', () => {
    const other = encodeCursor('admin-processes', position);
    expectInvalid(decodeCursor(other, KIND, keyset));
    // the same cursor is fine for the kind that minted it
    expect(decodeCursor(other, 'admin-processes', keyset).ok).toBe(true);
  });

  it('accepts a cursor edited into the right kind (a position marker, not a credential)', () => {
    const other = encodeCursor('admin-processes', position);
    const edited = tamper(other, (json) => json.replace('admin-processes', KIND));
    // the edit is structurally valid for KIND: it is accepted, which is why the doc says that a
    // cursor is a position marker and not a credential
    expect(decodeCursor(edited, KIND, keyset).ok).toBe(true);
  });

  it("rejects a cursor minted for another endpoint when the payload does not fit this endpoint's schema", () => {
    const other = encodeCursor(KIND, { name: 'Acme', rank: 3 });
    expectInvalid(decodeCursor(other, KIND, keyset));
  });

  it('refuses to mint a cursor above the contract length', () => {
    expect(() => encodeCursor(KIND, { blob: 'x'.repeat(CURSOR_MAX_LENGTH) })).toThrow(RangeError);
  });

  it.each(['', 'Has Upper', 'under_score', 'trailing-', '-leading', 'a'.repeat(41), 'sp ace'])(
    'refuses to mint a cursor for the invalid kind %j',
    (kind) => {
      expect(() => encodeCursor(kind, position)).toThrow(RangeError);
    },
  );
});

describe('pageQuerySchema (contract parameters Limit and Cursor)', () => {
  it('defaults limit to 50 and leaves cursor undefined', () => {
    expect(pageQuerySchema.parse({})).toEqual({ limit: 50 });
  });

  it.each([
    ['1', 1],
    ['50', 50],
    ['100', 100],
    ['007', 7],
  ])('accepts limit=%s', (raw, expected) => {
    expect(pageQuerySchema.parse({ limit: raw }).limit).toBe(expected);
  });

  it.each(['0', '101', '-1', '1.5', '1e1', ' 5', '5 ', '0x10', 'abc', '', '1000', '+5'])(
    'rejects limit=%j',
    (raw) => {
      expect(pageQuerySchema.safeParse({ limit: raw }).success).toBe(false);
    },
  );

  it('rejects a repeated limit and unknown parameters', () => {
    expect(pageQuerySchema.safeParse({ limit: ['1', '2'] }).success).toBe(false);
    expect(pageQuerySchema.safeParse({ extra: 'x' }).success).toBe(false);
  });

  it('validates the cursor like the contract does: 1..200 chars of [A-Za-z0-9_-]', () => {
    expect(pageQuerySchema.safeParse({ cursor: encodeCursor(KIND, position) }).success).toBe(true);
    for (const cursor of ['', 'has space', 'a+b', 'a'.repeat(CURSOR_MAX_LENGTH + 1)]) {
      expect(pageQuerySchema.safeParse({ cursor }).success, cursor).toBe(false);
    }
  });

  it('can be extended with filters and stays strict', () => {
    const schema = z.object({ ...pageQueryShape, status: z.enum(['active', 'archived']) }).strict();
    expect(schema.parse({ status: 'active' })).toEqual({ limit: 50, status: 'active' });
    expect(schema.safeParse({ status: 'active', nope: '1' }).success).toBe(false);
  });
});
