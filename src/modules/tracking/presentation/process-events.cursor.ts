import { z } from 'zod';
import { decodeCursor, encodeCursor } from '@/shared/http';
import type { Result, ValidationError } from '@/shared/kernel';
import type { ProcessEventPosition } from '../domain/process-event';

/**
 * Names the cursor of `GET /admin/processes/{processId}/events`: a cursor minted by another endpoint
 * is a 400 here (E-29), and this one is a 400 anywhere else.
 */
export const PROCESS_EVENT_CURSOR_KIND = 'admin-process-events';

/** The largest value of a Postgres `bigint`: past it the database refuses the id (class 22). */
const MAX_BIGINT = 9223372036854775807n;

/** A canonical `bigint`: decimal digits, no sign, no leading zero, at most 19 of them. */
const CANONICAL_ID = /^[1-9][0-9]{0,18}$/;

/**
 * The payload of the cursor: where the last page stopped. `i` is the id of the last event of the page,
 * a `bigint` as canonical decimal text (no sign, no leading zero) from 1 up to the largest `bigint`,
 * so what the database receives is always a number it can read. `.strict()`: an extra member is a 400.
 * The cursor names no process: the path says which one, and a position only ever moves inside what the
 * CEO may already read.
 */
const processEventCursorPayloadSchema = z
  .object({
    // one check, so `BigInt` never sees text the pattern refused (it throws on "abc")
    i: z.string().refine((value) => CANONICAL_ID.test(value) && BigInt(value) <= MAX_BIGINT),
  })
  .strict();

export function encodeProcessEventCursor(position: ProcessEventPosition): string {
  return encodeCursor(PROCESS_EVENT_CURSOR_KIND, { i: position.id });
}

/** A tampered, truncated, oversized, non-canonical or foreign cursor is `err(ValidationError)`. */
export function decodeProcessEventCursor(
  cursor: string,
): Result<ProcessEventPosition, ValidationError> {
  const decoded = decodeCursor(cursor, PROCESS_EVENT_CURSOR_KIND, processEventCursorPayloadSchema);
  if (!decoded.ok) return decoded;
  return { ok: true, value: { id: decoded.value.i } };
}
