import { describe, expect, it } from 'vitest';
import { encodeCursor } from '@/shared/http';
import { ValidationError } from '@/shared/kernel';
import {
  PROCESS_EVENT_CURSOR_KIND,
  decodeProcessEventCursor,
  encodeProcessEventCursor,
} from './process-events.cursor';

const refusal = (cursor: string) => {
  const result = decodeProcessEventCursor(cursor);
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error('expected a refusal');
  expect(result.error).toBeInstanceOf(ValidationError);
  expect(result.error.issues.map((issue) => issue.path)).toEqual(['query.cursor']);
};

describe('the cursor of GET /admin/processes/{processId}/events', () => {
  it('round-trips a position, the largest bigint included', () => {
    for (const id of ['1', '42', '9007199254740993', '9223372036854775807']) {
      expect(decodeProcessEventCursor(encodeProcessEventCursor({ id }))).toEqual({
        ok: true,
        value: { id },
      });
    }
  });

  it('fits the contract: at most 200 characters of the base64url alphabet', () => {
    const cursor = encodeProcessEventCursor({ id: '9223372036854775807' });

    expect(cursor.length).toBeLessThanOrEqual(200);
    expect(cursor).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it('E-29: refuses a truncated cursor, one with trailing bytes and plain garbage', () => {
    const cursor = encodeProcessEventCursor({ id: '42' });

    refusal(cursor.slice(0, -4));
    refusal(`${cursor}AAAA`);
    refusal('not-a-cursor');
    refusal('A');
  });

  it('E-29: refuses the cursor of another list, and the kind of this one is its own', () => {
    refusal(encodeCursor('admin-client-processes', { i: '42' }));
    refusal(encodeCursor('admin-clients', { i: '42' }));
    expect(PROCESS_EVENT_CURSOR_KIND).toBe('admin-process-events');
    expect(PROCESS_EVENT_CURSOR_KIND).not.toBe('admin-client-processes');
  });

  it('E-29: refuses a payload of the wrong shape', () => {
    refusal(encodeCursor(PROCESS_EVENT_CURSOR_KIND, { i: '42', extra: 1 }));
    refusal(encodeCursor(PROCESS_EVENT_CURSOR_KIND, {}));
    refusal(encodeCursor(PROCESS_EVENT_CURSOR_KIND, { i: 42 }));
    refusal(encodeCursor(PROCESS_EVENT_CURSOR_KIND, { c: '2026-11-16T11:30:24.984084+00:00' }));
    refusal(encodeCursor(PROCESS_EVENT_CURSOR_KIND, null));
    refusal(encodeCursor(PROCESS_EVENT_CURSOR_KIND, ['42']));
  });

  it('refuses an id the database could not read, or one that is not canonical, before it gets that far', () => {
    for (const id of [
      '0',
      '-1',
      '007',
      '1.5',
      '1e3',
      ' 42',
      '42 ',
      '+42',
      'abc',
      '',
      // one past the largest bigint, and a 19-digit number far above it
      '9223372036854775808',
      '9999999999999999999',
      // 20 digits
      '10000000000000000000',
    ]) {
      refusal(encodeCursor(PROCESS_EVENT_CURSOR_KIND, { i: id }));
    }
  });
});
