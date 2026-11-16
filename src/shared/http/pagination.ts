import { z } from 'zod';
import { err, ok, ValidationError, type Result } from '@/shared/kernel';

export const PAGE_LIMIT_DEFAULT = 50;
export const PAGE_LIMIT_MIN = 1;
export const PAGE_LIMIT_MAX = 100;
/** `components.schemas.Cursor.maxLength` of the contract. */
export const CURSOR_MAX_LENGTH = 200;

const CURSOR_PATTERN = /^[A-Za-z0-9_-]+$/;
const LIMIT_PATTERN = /^\d{1,3}$/;
const CURSOR_FORMAT_VERSION = 1;

const LIMIT_MESSAGE = `limit must be an integer from ${PAGE_LIMIT_MIN} to ${PAGE_LIMIT_MAX}`;

/**
 * Fields of a paginated list's query string, as in the contract (`parameters.Limit`/`Cursor`).
 * Spread it to add filters: `z.object({ ...pageQueryShape, status: … }).strict()`.
 * `limit` arrives as a string and is parsed strictly (no "1e1", " 5", "0x10").
 */
export const pageQueryShape = {
  limit: z
    .string()
    .regex(LIMIT_PATTERN, LIMIT_MESSAGE)
    .transform(Number)
    .pipe(z.number().int().min(PAGE_LIMIT_MIN).max(PAGE_LIMIT_MAX))
    .default(PAGE_LIMIT_DEFAULT),
  cursor: z.string().min(1).max(CURSOR_MAX_LENGTH).regex(CURSOR_PATTERN).optional(),
};

/** `?limit=1..100` (default 50) and `?cursor=<opaque>`; unknown query params → 400. */
export const pageQuerySchema = z.object(pageQueryShape).strict();

export type PageQuery = z.output<typeof pageQuerySchema>;

/** Shape of every list response: `{ items, nextCursor }` (`nextCursor` is `null` on the last page). */
export type Page<T> = { readonly items: readonly T[]; readonly nextCursor: string | null };

const invalidCursor = () =>
  new ValidationError('invalid pagination cursor', [
    { path: 'query.cursor', message: 'Invalid cursor' },
  ]);

/** Names an endpoint (or family of endpoints) whose pages share a cursor format: `lowercase-kebab`. */
const CURSOR_KIND_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const CURSOR_KIND_MAX_LENGTH = 40;

const isCursorKind = (kind: string) =>
  kind.length <= CURSOR_KIND_MAX_LENGTH && CURSOR_KIND_PATTERN.test(kind);

/**
 * Opaque cursor: base64url of `{ v, k, p }`, where `k` is the endpoint kind (e.g. `admin-clients`)
 * and `p` is the position the endpoint needs to resume (e.g. the last `createdAt` and `id` of a
 * keyset).
 *
 * It is a position marker, NOT a credential and NOT signed: a client that builds a well-formed
 * cursor of the right kind with a payload that matches the endpoint's schema is accepted, and
 * resumes from that position. That is harmless because tenant and role checks (RLS, the principal)
 * apply again on every page, so a forged position can only move within what the caller may already
 * read. What the codec does guarantee: garbage, truncated, oversized, non-canonical, edited-into-
 * the-wrong-shape and cross-endpoint cursors (a cursor minted by another `kind`) are all rejected
 * with the same 400.
 */
export function encodeCursor(kind: string, payload: unknown): string {
  if (!isCursorKind(kind)) throw new RangeError(`invalid cursor kind "${kind}"`);
  const json = JSON.stringify({ v: CURSOR_FORMAT_VERSION, k: kind, p: payload });
  const cursor = Buffer.from(json, 'utf8').toString('base64url');
  if (cursor.length > CURSOR_MAX_LENGTH) {
    throw new RangeError(`cursor payload is too large (${cursor.length} > ${CURSOR_MAX_LENGTH})`);
  }
  return cursor;
}

/**
 * Decodes a cursor of the given `kind` and checks its payload against the endpoint's schema. A
 * tampered, truncated, oversized, non-canonical, garbage or other-kind cursor →
 * `Err(ValidationError)` (400, `query.cursor`, E-29). Use a `.strict()` object schema for the
 * payload.
 */
export function decodeCursor<S extends z.ZodType>(
  cursor: string,
  kind: string,
  payloadSchema: S,
): Result<z.output<S>, ValidationError> {
  if (cursor.length === 0 || cursor.length > CURSOR_MAX_LENGTH) return err(invalidCursor());
  if (!CURSOR_PATTERN.test(cursor)) return err(invalidCursor());

  const bytes = Buffer.from(cursor, 'base64url');
  // Reject non-canonical encodings: the same bytes must encode back to exactly this string.
  if (bytes.toString('base64url') !== cursor) return err(invalidCursor());

  let envelope: unknown;
  try {
    envelope = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    return err(invalidCursor());
  }

  const parsedEnvelope = z
    .object({ v: z.literal(CURSOR_FORMAT_VERSION), k: z.string(), p: z.unknown() })
    .strict()
    .safeParse(envelope);
  if (!parsedEnvelope.success || parsedEnvelope.data.k !== kind) return err(invalidCursor());

  const payload = payloadSchema.safeParse(parsedEnvelope.data.p);
  if (!payload.success) return err(invalidCursor());
  return ok(payload.data);
}
