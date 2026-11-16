import { describe, expect, it } from 'vitest';
import { encodeCursor } from '@/shared/http';
import { ValidationError } from '@/shared/kernel';
import { PROCESS_CURSOR_KIND, decodeProcessCursor, encodeProcessCursor } from './process.cursor';

const POSITION = {
  createdAt: '2026-11-16T11:30:24.984084+00:00',
  id: '00000000-0000-4000-8000-0000000001a1',
} as const;

const refusal = (cursor: string) => {
  const result = decodeProcessCursor(cursor);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error('expected a refusal');
  expect(result.error).toBeInstanceOf(ValidationError);
  expect(result.error.issues.map((issue) => issue.path)).toEqual(['query.cursor']);
};

describe('the cursor of GET /admin/clients/{clientId}/processes', () => {
  it('round-trips a position, microsecond precision included', () => {
    expect(decodeProcessCursor(encodeProcessCursor(POSITION))).toEqual({
      ok: true,
      value: POSITION,
    });
  });

  it('fits the contract: at most 200 characters of the base64url alphabet', () => {
    const cursor = encodeProcessCursor(POSITION);

    expect(cursor.length).toBeLessThanOrEqual(200);
    expect(cursor).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('E-29: refuses a truncated cursor, one with trailing bytes and plain garbage', () => {
    const cursor = encodeProcessCursor(POSITION);

    refusal(cursor.slice(0, -4));
    refusal(`${cursor}AAAA`);
    refusal('not-a-cursor');
    refusal('A');
  });

  it('E-29: refuses the cursor of the client list, and the kind of this one is its own', () => {
    refusal(encodeCursor('admin-clients', { c: POSITION.createdAt, i: POSITION.id }));
    expect(PROCESS_CURSOR_KIND).toBe('admin-client-processes');
    expect(PROCESS_CURSOR_KIND).not.toBe('admin-clients');
  });

  it('E-29: refuses a payload of the wrong shape', () => {
    const at = POSITION.createdAt;
    refusal(encodeCursor(PROCESS_CURSOR_KIND, { c: at, i: POSITION.id, extra: 1 }));
    refusal(encodeCursor(PROCESS_CURSOR_KIND, { c: at }));
    refusal(encodeCursor(PROCESS_CURSOR_KIND, { i: POSITION.id }));
    refusal(encodeCursor(PROCESS_CURSOR_KIND, { c: 'yesterday', i: POSITION.id }));
    refusal(encodeCursor(PROCESS_CURSOR_KIND, { c: at, i: 'nope' }));
    refusal(encodeCursor(PROCESS_CURSOR_KIND, null));
    refusal(encodeCursor(PROCESS_CURSOR_KIND, [at, POSITION.id]));
  });

  it('F-53: refuses a timestamp the database cannot read, before it gets that far', () => {
    refusal(
      encodeCursor(PROCESS_CURSOR_KIND, { c: '0000-01-01T00:00:00.000000+00:00', i: POSITION.id }),
    );
    refusal(
      encodeCursor(PROCESS_CURSOR_KIND, { c: '1999-12-31T23:59:59.000000+00:00', i: POSITION.id }),
    );
    refusal(
      encodeCursor(PROCESS_CURSOR_KIND, { c: '2026-01-01T00:00:00.000000+23:59', i: POSITION.id }),
    );
    refusal(
      encodeCursor(PROCESS_CURSOR_KIND, { c: '2026-01-01T00:00:00.000000-16:00', i: POSITION.id }),
    );
  });

  it('accepts the bounds: year 2000, the 9999 ceiling and an offset of 15:59', () => {
    for (const createdAt of [
      '2000-01-01T00:00:00.000000+00:00',
      '9999-12-31T23:59:59.999999+00:00',
      '2026-01-01T00:00:00.000000+15:59',
    ]) {
      expect(
        decodeProcessCursor(encodeCursor(PROCESS_CURSOR_KIND, { c: createdAt, i: POSITION.id })).ok,
      ).toBe(true);
    }
  });
});
