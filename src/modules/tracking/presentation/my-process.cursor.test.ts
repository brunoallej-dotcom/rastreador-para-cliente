import { describe, expect, it } from 'vitest';
import { encodeCursor } from '@/shared/http';
import { ValidationError } from '@/shared/kernel';
import {
  MY_PROCESS_CURSOR_KIND,
  decodeMyProcessCursor,
  encodeMyProcessCursor,
} from './my-process.cursor';
import { PROCESS_CURSOR_KIND, encodeProcessCursor } from './process.cursor';

const POSITION = {
  createdAt: '2026-11-16T11:30:24.984084+00:00',
  id: '00000000-0000-4000-8000-0000000001a1',
} as const;

const refusal = (cursor: string) => {
  const result = decodeMyProcessCursor(cursor);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error('expected a refusal');
  expect(result.error).toBeInstanceOf(ValidationError);
  expect(result.error.issues.map((issue) => issue.path)).toEqual(['query.cursor']);
};

describe('the cursor of GET /me/processes', () => {
  it('round-trips a position, microsecond precision included', () => {
    expect(decodeMyProcessCursor(encodeMyProcessCursor(POSITION))).toEqual({
      ok: true,
      value: POSITION,
    });
  });

  it('fits the contract: at most 200 characters of the base64url alphabet', () => {
    const cursor = encodeMyProcessCursor(POSITION);

    expect(cursor.length).toBeLessThanOrEqual(200);
    expect(cursor).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('names no client: the payload is a timestamp and a process id and nothing else', () => {
    const cursor = encodeMyProcessCursor(POSITION);
    const envelope = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8')) as {
      k: string;
      p: Record<string, unknown>;
    };

    expect(envelope.k).toBe('my-processes');
    expect(Object.keys(envelope.p).sort()).toEqual(['c', 'i']);
  });

  it('E-29: refuses a truncated cursor, one with trailing bytes and plain garbage', () => {
    const cursor = encodeMyProcessCursor(POSITION);

    refusal(cursor.slice(0, -4));
    refusal(`${cursor}AAAA`);
    refusal('not-a-cursor');
    refusal('A');
  });

  it('E-29: refuses the cursor of every other list, and the kind of this one is its own', () => {
    refusal(encodeCursor('admin-clients', { c: POSITION.createdAt, i: POSITION.id }));
    refusal(encodeProcessCursor(POSITION));
    expect(MY_PROCESS_CURSOR_KIND).toBe('my-processes');
    expect(MY_PROCESS_CURSOR_KIND).not.toBe(PROCESS_CURSOR_KIND);
    // and the CEO's list refuses the client's
    expect(
      encodeCursor(MY_PROCESS_CURSOR_KIND, { c: POSITION.createdAt, i: POSITION.id }),
    ).not.toBe(encodeProcessCursor(POSITION));
  });

  it('E-29: refuses a payload of the wrong shape, a client id included', () => {
    const at = POSITION.createdAt;
    refusal(encodeCursor(MY_PROCESS_CURSOR_KIND, { c: at, i: POSITION.id, extra: 1 }));
    refusal(encodeCursor(MY_PROCESS_CURSOR_KIND, { c: at, i: POSITION.id, t: 'b' }));
    refusal(encodeCursor(MY_PROCESS_CURSOR_KIND, { c: at }));
    refusal(encodeCursor(MY_PROCESS_CURSOR_KIND, { i: POSITION.id }));
    refusal(encodeCursor(MY_PROCESS_CURSOR_KIND, { c: 'yesterday', i: POSITION.id }));
    refusal(encodeCursor(MY_PROCESS_CURSOR_KIND, { c: at, i: 'nope' }));
    refusal(encodeCursor(MY_PROCESS_CURSOR_KIND, null));
    refusal(encodeCursor(MY_PROCESS_CURSOR_KIND, [at, POSITION.id]));
  });

  it('F-53: refuses a timestamp the database cannot read, before it gets that far', () => {
    for (const c of [
      '0000-01-01T00:00:00.000000+00:00',
      '1999-12-31T23:59:59.000000+00:00',
      '2026-01-01T00:00:00.000000+23:59',
      '2026-01-01T00:00:00.000000-16:00',
    ]) {
      refusal(encodeCursor(MY_PROCESS_CURSOR_KIND, { c, i: POSITION.id }));
    }
  });

  it('accepts the bounds: year 2000, the 9999 ceiling and an offset of 15:59', () => {
    for (const createdAt of [
      '2000-01-01T00:00:00.000000+00:00',
      '9999-12-31T23:59:59.999999+00:00',
      '2026-01-01T00:00:00.000000+15:59',
    ]) {
      expect(
        decodeMyProcessCursor(
          encodeCursor(MY_PROCESS_CURSOR_KIND, { c: createdAt, i: POSITION.id }),
        ).ok,
      ).toBe(true);
    }
  });
});
