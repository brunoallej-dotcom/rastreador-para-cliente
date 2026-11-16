import { z } from 'zod';
import { decodeCursor, encodeCursor } from '@/shared/http';
import type { Result, ValidationError } from '@/shared/kernel';
import type { ClientListPosition } from '../domain/client';

/**
 * Names the cursor of `GET /admin/clients`: a cursor minted by another endpoint is a 400 here
 * (E-29), and this one is a 400 anywhere else.
 */
export const CLIENT_CURSOR_KIND = 'admin-clients';

/**
 * The range of instants a cursor may carry. The list only ever holds clients created by this
 * system, so a year before 2000 is never a position it issued; Postgres refuses year 0000 and
 * offsets past 15:59 (a well-formed ISO timestamp that it cannot read is a 500 waiting to happen,
 * F-53), and the cursor is checked here before it gets that far.
 */
const MIN_CURSOR_YEAR = 2000;
const MAX_OFFSET_HOURS = 15;
const OFFSET_PATTERN = /[+-](\d{2}):\d{2}$/;
const YEAR_LENGTH = 4;

function isPlausibleInstant(value: string): boolean {
  if (Number(value.slice(0, YEAR_LENGTH)) < MIN_CURSOR_YEAR) return false;
  const offsetHours = OFFSET_PATTERN.exec(value)?.[1];
  return offsetHours === undefined || Number(offsetHours) <= MAX_OFFSET_HOURS;
}

/**
 * The payload of the cursor: where the last page stopped. `c` is the `created_at` text the database
 * sent (any precision, with an offset, within the range above) and `i` the client id. `.strict()`:
 * an extra member is a 400.
 */
const clientCursorPayloadSchema = z
  .object({
    c: z.iso.datetime({ offset: true }).refine(isPlausibleInstant),
    i: z.uuid(),
  })
  .strict();

export function encodeClientCursor(position: ClientListPosition): string {
  return encodeCursor(CLIENT_CURSOR_KIND, { c: position.createdAt, i: position.id });
}

/** A tampered, truncated, oversized, non-canonical or foreign cursor is `err(ValidationError)`. */
export function decodeClientCursor(cursor: string): Result<ClientListPosition, ValidationError> {
  const decoded = decodeCursor(cursor, CLIENT_CURSOR_KIND, clientCursorPayloadSchema);
  if (!decoded.ok) return decoded;
  return { ok: true, value: { createdAt: decoded.value.c, id: decoded.value.i } };
}
