import { describe, expect, it } from 'vitest';
import { encodeCursor } from '@/shared/http';
import { ValidationError } from '@/shared/kernel';
import { CLIENT_CURSOR_KIND, decodeClientCursor, encodeClientCursor } from './client.cursor';

const POSITION = {
  createdAt: '2026-11-16T11:30:24.984084+00:00',
  id: '00000000-0000-4000-8000-00000000000a',
} as const;

const refusal = (cursor: string) => {
  const result = decodeClientCursor(cursor);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error('expected a refusal');
  expect(result.error).toBeInstanceOf(ValidationError);
  expect(result.error.issues.map((issue) => issue.path)).toEqual(['query.cursor']);
};

describe('the cursor of GET /admin/clients', () => {
  it('round-trips a position, microsecond precision included', () => {
    const cursor = encodeClientCursor(POSITION);

    expect(decodeClientCursor(cursor)).toEqual({ ok: true, value: POSITION });
  });

  it('fits the contract: at most 200 characters of the base64url alphabet', () => {
    const cursor = encodeClientCursor(POSITION);

    expect(cursor.length).toBeLessThanOrEqual(200);
    expect(cursor).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('E-29: refuses a truncated cursor, one with trailing bytes and plain garbage', () => {
    const cursor = encodeClientCursor(POSITION);

    refusal(cursor.slice(0, -4));
    refusal(`${cursor}AAAA`);
    refusal('not-a-cursor');
    refusal('A');
  });

  it('E-29: refuses a cursor minted by another endpoint', () => {
    refusal(encodeCursor('admin-processes', { c: POSITION.createdAt, i: POSITION.id }));
    expect(CLIENT_CURSOR_KIND).toBe('admin-clients');
  });

  it('E-29: refuses a payload of the wrong shape', () => {
    const at = POSITION.createdAt;
    refusal(encodeCursor(CLIENT_CURSOR_KIND, { c: at, i: POSITION.id, extra: 1 }));
    refusal(encodeCursor(CLIENT_CURSOR_KIND, { c: at }));
    refusal(encodeCursor(CLIENT_CURSOR_KIND, { c: 'yesterday', i: POSITION.id }));
    refusal(encodeCursor(CLIENT_CURSOR_KIND, { c: at, i: 'nope' }));
    refusal(encodeCursor(CLIENT_CURSOR_KIND, { c: 20260101, i: POSITION.id }));
    refusal(encodeCursor(CLIENT_CURSOR_KIND, null));
    refusal(encodeCursor(CLIENT_CURSOR_KIND, [at, POSITION.id]));
  });

  it('refuses a timestamp without an offset (it would be read in the server time zone)', () => {
    refusal(encodeCursor(CLIENT_CURSOR_KIND, { c: '2026-11-16T11:30:24.984084', i: POSITION.id }));
  });
});
