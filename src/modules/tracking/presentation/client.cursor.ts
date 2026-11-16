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
 * The payload of the cursor: where the last page stopped. `c` is the `created_at` text the database
 * sent (any precision, with an offset) and `i` the client id. `.strict()`: an extra member is a 400.
 */
const clientCursorPayloadSchema = z
  .object({ c: z.iso.datetime({ offset: true }), i: z.uuid() })
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
