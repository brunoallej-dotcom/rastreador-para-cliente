import { z } from 'zod';
import { decodeCursor, encodeCursor } from '@/shared/http';
import type { Result, ValidationError } from '@/shared/kernel';
import type { ProcessListPosition } from '../domain/process';
import { isPlausibleInstant } from './client.cursor';

/**
 * Names the cursor of `GET /me/processes`: a cursor minted by another endpoint (the CEO's list of a
 * client's processes included) is a 400 here (E-29), and this one is a 400 anywhere else.
 */
export const MY_PROCESS_CURSOR_KIND = 'my-processes';

/**
 * The payload of the cursor: where the last page stopped. `c` is the `created_at` text the database
 * sent (any precision, with an offset, from the year 2000 and within the offsets Postgres reads: the
 * same bounds as the other lists, F-53) and `i` the process id. `.strict()`: an extra member is a 400.
 * The cursor names no client: the tenant is the session's, and a position only ever moves inside what
 * the client may already read, so a cursor minted by another client moves inside THIS client's rows.
 */
const myProcessCursorPayloadSchema = z
  .object({
    c: z.iso.datetime({ offset: true }).refine(isPlausibleInstant),
    i: z.uuid(),
  })
  .strict();

export function encodeMyProcessCursor(position: ProcessListPosition): string {
  return encodeCursor(MY_PROCESS_CURSOR_KIND, { c: position.createdAt, i: position.id });
}

/** A tampered, truncated, oversized, non-canonical or foreign cursor is `err(ValidationError)`. */
export function decodeMyProcessCursor(
  cursor: string,
): Result<ProcessListPosition, ValidationError> {
  const decoded = decodeCursor(cursor, MY_PROCESS_CURSOR_KIND, myProcessCursorPayloadSchema);
  if (!decoded.ok) return decoded;
  return { ok: true, value: { createdAt: decoded.value.c, id: decoded.value.i } };
}
