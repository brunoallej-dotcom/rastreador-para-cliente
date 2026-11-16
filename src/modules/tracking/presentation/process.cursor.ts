import { z } from 'zod';
import { decodeCursor, encodeCursor } from '@/shared/http';
import type { Result, ValidationError } from '@/shared/kernel';
import type { ProcessListPosition } from '../domain/process';
import { isPlausibleInstant } from './client.cursor';

/**
 * Names the cursor of `GET /admin/clients/{clientId}/processes`: a cursor minted by another endpoint
 * is a 400 here (E-29), and this one is a 400 anywhere else.
 */
export const PROCESS_CURSOR_KIND = 'admin-client-processes';

/**
 * The payload of the cursor: where the last page stopped. `c` is the `created_at` text the database
 * sent (any precision, with an offset, from the year 2000 and within the offsets Postgres reads, the
 * same bounds as the client list: F-53) and `i` the process id. `.strict()`: an extra member is a
 * 400. The cursor names no client: the path says which one, and a position only ever moves inside
 * what the CEO may already read.
 */
const processCursorPayloadSchema = z
  .object({
    c: z.iso.datetime({ offset: true }).refine(isPlausibleInstant),
    i: z.uuid(),
  })
  .strict();

export function encodeProcessCursor(position: ProcessListPosition): string {
  return encodeCursor(PROCESS_CURSOR_KIND, { c: position.createdAt, i: position.id });
}

/** A tampered, truncated, oversized, non-canonical or foreign cursor is `err(ValidationError)`. */
export function decodeProcessCursor(cursor: string): Result<ProcessListPosition, ValidationError> {
  const decoded = decodeCursor(cursor, PROCESS_CURSOR_KIND, processCursorPayloadSchema);
  if (!decoded.ok) return decoded;
  return { ok: true, value: { createdAt: decoded.value.c, id: decoded.value.i } };
}
