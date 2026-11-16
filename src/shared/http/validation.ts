import { z } from 'zod';
import { ValidationError, type ValidationIssue } from '@/shared/kernel';

export type InputPart = 'params' | 'query' | 'body';

/**
 * Characters that are never visible text: Unicode general categories
 *   Cc  controls (U+0000-001F, U+007F-009F: includes \n, \r, \t),
 *   Cf  ALL format characters (soft hyphen, zero-width space and joiners, LRM/RLM, bidi embeddings,
 *       overrides and isolates, word joiner, BOM, U+FFF9-FFFB interlinear annotation, the "tag"
 *       characters U+E0000-E007F...),
 *   Zl  line separator (U+2028),
 *   Zp  paragraph separator (U+2029).
 * This is a superset of the class the database CHECKs reject (Wave 2): validation here is the
 * stricter layer. Written with property escapes, never as literal invisible characters.
 */
const CONTROL_OR_FORMAT_CHARACTERS = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

/**
 * Invisible "filler" characters that are NOT in Cc/Cf/Zl/Zp but render as blank: Hangul fillers
 * (U+115F, U+1160, U+3164, U+FFA0), Khmer inherent vowels (U+17B4, U+17B5) and the blank braille
 * pattern (U+2800). Most are classified as letters, so the letter requirement alone would not
 * catch them.
 */
const INVISIBLE_FILLERS: ReadonlySet<string> = new Set(
  [0x115f, 0x1160, 0x17b4, 0x17b5, 0x2800, 0x3164, 0xffa0].map((codePoint) =>
    String.fromCodePoint(codePoint),
  ),
);
const hasInvisibleFiller = (text: string) => Array.from(text).some((c) => INVISIBLE_FILLERS.has(c));

/**
 * A lone UTF-16 surrogate (what the JSON text `"\ud800"` decodes to) is not text: Postgres refuses it
 * (22P02) and a name that passed validation would become a 500 (F-54). With the `u` flag a surrogate
 * PAIR is one code point, so only a lone one matches `\p{Surrogate}` (the same test as
 * `!value.isWellFormed()`, without needing the ES2024 string typings).
 */
const LONE_SURROGATE = /\p{Surrogate}/u;

/** At least one letter or number, so a name cannot be only symbols or punctuation. */
const HAS_LETTER_OR_NUMBER = /[\p{L}\p{N}]/u;

const codePointLength = (text: string) => Array.from(text).length;

/**
 * Zod schema for human-visible text typed by a user (names, labels; spec E-30). The output is:
 * 1. normalized to NFC, so "e-acute" typed as `e` + U+0301 is stored and compared as U+00E9;
 * 2. trimmed;
 * 3. checked against `min`/`max` on the TRIMMED value, counted in code points (as the database's
 *    `char_length` and JSON Schema's `minLength`/`maxLength` do);
 * 4. rejected if it holds a lone UTF-16 surrogate (not valid text; the database would refuse it), or
 *    if it contains a control, format, line-separator or paragraph-separator character
 *    (`\n`, zero-width space, bidi override, tag characters, U+2028...) or an invisible filler
 *    (U+3164, U+2800, U+115F, U+1160, U+17B4, U+17B5, U+FFA0), which could hide or reorder text in
 *    the UI;
 * 5. rejected unless it has at least one letter or number (a non-empty value only).
 * The error messages never echo the rejected value.
 */
export function visibleText({ min, max }: { readonly min: number; readonly max: number }) {
  if (!Number.isInteger(min) || !Number.isInteger(max) || min < 0 || max < min) {
    throw new RangeError(`visibleText: invalid bounds min=${min} max=${max}`);
  }
  return z
    .string()
    .transform((value) => value.normalize('NFC').trim())
    .pipe(
      z.string().superRefine((value, context) => {
        if (LONE_SURROGATE.test(value)) {
          context.addIssue({ code: 'custom', message: 'Must be valid Unicode text' });
          return;
        }
        const length = codePointLength(value);
        if (length < min) {
          context.addIssue({
            code: 'custom',
            message: min === 1 ? 'Must not be empty' : `Must have at least ${min} characters`,
          });
          return;
        }
        if (length > max) {
          context.addIssue({ code: 'custom', message: `Must have at most ${max} characters` });
          return;
        }
        if (CONTROL_OR_FORMAT_CHARACTERS.test(value) || hasInvisibleFiller(value)) {
          context.addIssue({
            code: 'custom',
            message: 'Must not contain control or invisible formatting characters',
          });
          return;
        }
        if (length > 0 && !HAS_LETTER_OR_NUMBER.test(value)) {
          context.addIssue({
            code: 'custom',
            message: 'Must contain at least one letter or number',
          });
        }
      }),
    );
}

/** A Zod object schema for one part of the request. Must be `.strict()`. */
export type InputSchema = z.ZodObject;

export type InputSchemas = {
  readonly params?: InputSchema | undefined;
  readonly query?: InputSchema | undefined;
  readonly body?: InputSchema | undefined;
};

export type RawInput = {
  readonly params: unknown;
  readonly query: unknown;
  readonly body: unknown;
};

/** The parsed values; `undefined` for a part that has no schema. */
export type ValidatedInput = Readonly<Record<InputPart, unknown>>;

const UNKNOWN_FIELD_MESSAGE = 'Unknown field';

/** `body.stages[2].name`: dotted keys, bracketed indexes, rooted at the request part. */
export function formatIssuePath(part: InputPart, path: readonly PropertyKey[]): string {
  let formatted: string = part;
  for (const segment of path) {
    formatted +=
      typeof segment === 'number'
        ? `[${segment}]`
        : `.${typeof segment === 'symbol' ? String(segment) : segment}`;
  }
  return formatted;
}

/** One entry per problem; an unrecognized key is reported once per key, at the key's own path. */
export function issuesOf(part: InputPart, error: z.ZodError): ValidationIssue[] {
  return error.issues.flatMap((issue): ValidationIssue[] => {
    if (issue.code === 'unrecognized_keys') {
      return issue.keys.map((key) => ({
        path: formatIssuePath(part, [...issue.path, key]),
        message: UNKNOWN_FIELD_MESSAGE,
      }));
    }
    return [{ path: formatIssuePath(part, issue.path), message: issue.message }];
  });
}

/**
 * Query string to object for Zod: a key given once is a string, a repeated key is an array of
 * strings (which then fails a `z.string()` field instead of being silently reduced to one value).
 */
export function queryToObject(searchParams: URLSearchParams): Record<string, string | string[]> {
  // fromEntries defines own properties, so a key such as `__proto__` stays plain data (and a
  // strict schema then rejects it) instead of reaching the object's prototype.
  return Object.fromEntries(
    [...new Set(searchParams.keys())].map((key) => {
      const values = searchParams.getAll(key);
      return [key, values.length === 1 ? (values[0] ?? '') : values] as const;
    }),
  );
}

/**
 * Step 7 of the pipeline: validates params, query and body against their strict schemas and
 * returns the parsed values. Every problem of every part is collected, then thrown together as a
 * `ValidationError` (400 `VALIDATION_ERROR` with `errors[]`). A part without a schema is returned
 * as `undefined`.
 */
export function validateInput(schemas: InputSchemas, raw: RawInput): ValidatedInput {
  const issues: ValidationIssue[] = [];
  const parsed: Record<InputPart, unknown> = {
    params: undefined,
    query: undefined,
    body: undefined,
  };

  for (const part of ['params', 'query', 'body'] as const) {
    const schema = schemas[part];
    if (schema === undefined) continue;
    const result = schema.safeParse(raw[part]);
    if (result.success) parsed[part] = result.data;
    else issues.push(...issuesOf(part, result.error));
  }

  if (issues.length > 0) throw new ValidationError('invalid request input', issues);
  return parsed;
}
