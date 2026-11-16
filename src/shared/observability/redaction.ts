// Scrubbing of everything that goes to the logs (spec §3.10, SEC-16): no PII, no credentials.
//
// Three layers, all applied by the logger:
//  1. key based: a value under a sensitive key is replaced, at any depth, whatever the key's
//     casing or separators (`Authorization`, `set-cookie`, `access_token`, `X-API-Key`...);
//  2. value based: e-mail addresses and token-looking strings are cut out of every string, which
//     covers error messages such as Postgres' `Key (email)=(a@b.com) already exists.`;
//  3. shape based: errors are reduced to type, name, code, message and stack (plus the same for
//     their `cause` chain), nothing else of the error object is copied; anything nested deeper
//     than MAX_LOG_DEPTH is replaced by a placeholder, and cycles are cut.

export const REDACTED = '[REDACTED]';
export const REDACTED_EMAIL = '[REDACTED_EMAIL]';
export const REDACTED_TOKEN = '[REDACTED_TOKEN]';
export const TRUNCATED = '[Truncated]';
export const CIRCULAR = '[Circular]';
const UNSERIALIZABLE = '[Unserializable]';

/** Levels of nesting kept below the log object. Anything deeper is replaced, never emitted. */
export const MAX_LOG_DEPTH = 8;

/** Keys compared after `normalizeKey`: lowercase, without `-`, `_`, `.` or spaces. */
const SENSITIVE_KEYS: ReadonlySet<string> = new Set([
  'password',
  'passwd',
  'email',
  'cookie',
  'setcookie',
  'authorization',
  'proxyauthorization',
  'secret',
  'token',
  'otp',
  'code',
  'totp',
  'jwt',
  'apikey',
  'secretkey',
  'privatekey',
  'totpcode',
  'mfacode',
  'otpcode',
  'verificationcode',
  // the QR code of a TOTP enrollment is an image of the otpauth URI, so it carries the secret too
  'qrcode',
]);

/** Compound names that end in one of these are sensitive too (`newPassword`, `csrf-token`...). */
const SENSITIVE_SUFFIXES = [
  'password',
  'passwd',
  'secret',
  'token',
  'apikey',
  'jwt',
  'cookie',
  'authorization',
  'email',
] as const;

const normalizeKey = (key: string) => key.toLowerCase().replace(/[-_.\s]/g, '');

export function isSensitiveKey(key: string): boolean {
  const normalized = normalizeKey(key);
  return (
    SENSITIVE_KEYS.has(normalized) ||
    SENSITIVE_SUFFIXES.some((suffix) => normalized.endsWith(suffix))
  );
}

// Quantifiers are bounded so scrubbing a long stack trace stays linear.
const POSTGRES_KEY_DETAIL =
  /\(([A-Za-z_,\s]{0,40}(?:e-?mail|password|token|secret)[A-Za-z_,\s]{0,40})\)=\([^)]{0,200}\)/gi;
const JWT = /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}(?:\.[A-Za-z0-9_-]{0,512})?/g;
const AUTH_SCHEME = /\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,512}/gi;
const SUPABASE_KEY = /\bsb_(?:secret|publishable)_[A-Za-z0-9_-]{8,128}/g;
// An `otpauth://` URI carries the TOTP secret (`secret=`) and the e-mail of the account (its label).
// The whole URI goes, up to the next whitespace; only a key named `uri` would be too broad to redact.
const OTPAUTH_URI = /otpauth:\/\/\S+/gi;
// The last label must be alphabetic (a TLD), so `vitest@5.1.0` in a pnpm path of a stack frame is
// not mistaken for an address and stacks stay readable.
const EMAIL =
  /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,7}\.[A-Za-z]{2,24}/g;

/** Cuts e-mail addresses, token-looking strings and `otpauth://` URIs out of free text. */
export function scrubText(text: string): string {
  return text
    .replace(OTPAUTH_URI, REDACTED)
    .replace(POSTGRES_KEY_DETAIL, '($1)=([REDACTED])')
    .replace(JWT, REDACTED_TOKEN)
    .replace(AUTH_SCHEME, `$1 ${REDACTED_TOKEN}`)
    .replace(SUPABASE_KEY, REDACTED_TOKEN)
    .replace(EMAIL, REDACTED_EMAIL);
}

type Seen = Set<object>;

function errorCode(error: Error): string | number | undefined {
  const code = (error as { code?: unknown }).code;
  if (typeof code === 'string') return scrubText(code);
  if (typeof code === 'number') return code;
  return undefined;
}

/**
 * An error reduced to `type`, `name`, `code`, `message` and `stack`, with e-mails and tokens cut out
 * of the text, plus its `cause` chain the same way. Other properties of the error object (which may
 * hold request configs, headers, rows) are deliberately not copied.
 */
function serializeError(error: Error, depth: number, seen: Seen): Record<string, unknown> {
  try {
    const code = errorCode(error);
    return {
      type: error.constructor.name,
      name: error.name,
      message: scrubText(error.message),
      ...(code === undefined ? {} : { code }),
      stack: scrubText(error.stack ?? ''),
      ...(error.cause === undefined ? {} : { cause: sanitizeValue(error.cause, depth + 1, seen) }),
    };
  } catch {
    return { type: 'Error', message: UNSERIALIZABLE };
  }
}

function sanitizeEntries(
  entries: Iterable<readonly [string, unknown]>,
  depth: number,
  seen: Seen,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of entries) {
    // defineProperty, so a key named `__proto__` stays plain data
    Object.defineProperty(result, key, {
      value: isSensitiveKey(key) ? REDACTED : sanitizeValue(value, depth + 1, seen),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return result;
}

function ownEntries(value: object): [string, unknown][] {
  return Object.keys(value).map((key) => {
    try {
      return [key, (value as Record<string, unknown>)[key]];
    } catch {
      return [key, UNSERIALIZABLE]; // a getter that throws
    }
  });
}

/**
 * Deep copy of `value` that is safe to log: sensitive keys redacted, strings scrubbed, errors
 * serialized, cycles cut, depth bounded. `depth` is the nesting level of `value`.
 */
export function sanitizeValue(value: unknown, depth = 0, seen: Seen = new Set()): unknown {
  switch (typeof value) {
    case 'string':
      return scrubText(value);
    case 'number':
    case 'boolean':
    case 'undefined':
      return value;
    case 'bigint':
    case 'symbol':
      return String(value);
    case 'function':
      return undefined;
    default:
      break;
  }
  if (value === null) return null;
  const object = value as object;

  if (depth > MAX_LOG_DEPTH) return TRUNCATED;
  if (seen.has(object)) return CIRCULAR;
  seen.add(object);
  try {
    if (object instanceof Error) return serializeError(object, depth, seen);
    if (object instanceof Date) {
      return Number.isNaN(object.getTime()) ? 'Invalid Date' : object.toISOString();
    }
    if (ArrayBuffer.isView(object)) return `[Binary ${object.byteLength} bytes]`;
    if (object instanceof ArrayBuffer) return `[Binary ${object.byteLength} bytes]`;
    if (object instanceof Map) return '[Map]';
    if (object instanceof Set) return '[Set]';
    if (object instanceof URL) return scrubText(object.href);
    if (object instanceof Headers) return sanitizeEntries(object.entries(), depth, seen);
    if (Array.isArray(object)) return object.map((item) => sanitizeValue(item, depth + 1, seen));
    return sanitizeEntries(ownEntries(object), depth, seen);
  } catch {
    return UNSERIALIZABLE;
  } finally {
    seen.delete(object);
  }
}

/** The merging object of a log call, scrubbed. Used as pino's `formatters.log`. */
export function sanitizeLogObject(object: Record<string, unknown>): Record<string, unknown> {
  const sanitized = sanitizeValue(object);
  return typeof sanitized === 'object' && sanitized !== null
    ? (sanitized as Record<string, unknown>)
    : {};
}

const scrubIfString = (value: unknown) => (typeof value === 'string' ? scrubText(value) : value);

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null;

/**
 * Scrubs the message of a log call before pino sees it. pino derives a message from an error when
 * none is given (`logger.error(err)` or `{ err }` alone), and that message is the raw one, so the
 * derivation is done here, on scrubbed text.
 */
export function scrubLogArguments(args: readonly unknown[]): unknown[] {
  const [first, ...rest] = args;
  if (first instanceof Error) {
    return [{ err: first }, scrubText(first.message), ...rest.map(scrubIfString)];
  }
  if (typeof first === 'string') return [scrubText(first), ...rest.map(scrubIfString)];
  if (!isRecord(first)) return [...args];

  if (typeof rest[0] === 'string') return [first, ...rest.map(scrubIfString)];
  const err = first['err'];
  if (rest.length === 0 && err instanceof Error) return [first, scrubText(err.message)];
  return [first, ...rest];
}
