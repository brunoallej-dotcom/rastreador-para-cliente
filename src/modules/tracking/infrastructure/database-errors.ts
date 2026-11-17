// What the tracking repositories and query services share when a database call fails or answers
// something they cannot use. They were copied into each file (Waves 8, 9 and 10); one copy keeps the
// rules (no database message in a `cause`, class 22 on a position the caller sent is a 400, an answer
// that does not match the schema fails closed) from drifting apart.
import type { z } from 'zod';
import { ValidationError } from '@/shared/kernel';

/**
 * SQLSTATE class 22, "data exception": the database could not read a value it was given (a timestamp or
 * an id in a cursor that passed the schema of the application). On a position the CALLER sent it is
 * their input that is wrong, a 400 and not a 500 (`invalidPosition`).
 */
export const DATA_EXCEPTION_CLASS = '22';

/**
 * What may travel as the `cause` of an error: the SQLSTATE and the HTTP status, never the message, the
 * details or the hint of the database error. Those can carry the row ("Failing row contains (..., <title>)")
 * and the logger writes the `cause` chain of every 5xx error, so a title or a name would end up in the logs
 * (SEC-16 keeps them out of the trail, and the logs follow the same rule).
 */
export const safeCause = (error: { code?: string }, status: number) => ({
  code: error.code ?? '',
  status,
});

/** The refusal of a list position (the cursor) that the database could not read (timestamp or id). */
export const invalidPosition = (code: string) =>
  new ValidationError(
    'the database refused the list position',
    [{ path: 'query.cursor', message: 'Invalid cursor' }],
    { cause: { code } },
  );

/** A row is read from the database as untrusted data: what does not match the schema fails closed (500). */
export function parseRows<T>(schema: z.ZodType<T>, data: unknown, what: string): T {
  const parsed = schema.safeParse(data);
  if (!parsed.success) throw new Error(`${what} returned a row that is not understood`);
  return parsed.data;
}
