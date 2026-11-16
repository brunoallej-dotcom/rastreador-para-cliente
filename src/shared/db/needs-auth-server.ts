import { combineChunks, stringFromBase64URL } from '@supabase/ssr';
import { SESSION_COOKIE_NAME, type SessionCookie } from './session-cookies';

/**
 * Would handing these session cookies to the Auth client make the server call the Auth server, and
 * if not, is it SURE that it makes no call? The invariant this serves is: every call to Auth made
 * while resolving a principal is charged to the client IP's `session-upstream` budget, and an IP
 * over budget never reaches Auth (F-01). The cookie is attacker-controlled, so the answer must
 * never be optimistic: it parses the cookie the way the libraries do and says "no call" ONLY when
 * it can positively show it, and "a call" (or "refuse") for everything else.
 *
 * The parse mirrors, step by step, what `@supabase/ssr` and auth-js 2.119 do with the cookie:
 *  1. `combineChunks` (ssr's own function): the whole cookie if its value is truthy, else the chunks
 *     `.0`, `.1`... up to the first missing or empty one; `.abc`, holes and the rest are ignored.
 *  2. ssr's `decodeChunkedCookieValue`: a `base64-` prefix is decoded with ssr's own base64url and
 *     the result must be JSON; anything else is taken as it is.
 *  3. auth-js `getItemAsync`: `JSON.parse`.
 *  4. `_isValidSession`: an object that merely HAS `access_token`, `refresh_token`, `expires_at`
 *     (their types are not checked).
 *  5. `hasExpired`: `expires_at ? expires_at * 1000 - now < EXPIRY_MARGIN_MS : false`, truthiness and
 *     numeric coercion included. An expired session is refreshed: a call to Auth.
 *  6. `getClaims`: `decodeJWT` (three base64url parts, header and payload JSON), `validateExp`, then
 *     a call to Auth (`getUser`) unless the algorithm is asymmetric and the `kid` is a known
 *     signing key (and a JWKS fetch if that key is not in the library's own cache).
 */

/** How close to its expiry auth-js refreshes: `EXPIRY_MARGIN_MS`, 90 s. */
const REFRESH_MARGIN_MS = 90_000;

/** auth-js `BASE64URL_REGEX`, which `decodeJWT` applies to each of the three parts. */
const BASE64URL_REGEX = /^([a-z0-9_-]{4})*($|[a-z0-9_-]{3}$|[a-z0-9_-]{2}$)$/i;
const BASE64_PREFIX = 'base64-';
const JWT_PARTS = 3;
const MS_PER_SECOND = 1000;

/** The algorithms auth-js can verify with a key from the JWKS (`getAlgorithm`). */
const SUPPORTED_ASYMMETRIC_ALGS: ReadonlySet<string> = new Set(['ES256', 'RS256']);

/**
 * How long a `kid` counts as "in the library's JWKS cache" after it verified a token: half of the
 * cache's own 10-minute TTL (`JWKS_TTL`), because the cache ages from the moment the keys were
 * FETCHED, which is before the verification that taught us the kid. An older kid is treated as
 * unknown (the next request with it pays one unit, fetches the keys again and renews the entry).
 */
export const KID_FRESH_MS = 5 * 60 * MS_PER_SECOND;

/** A signing key this process has seen verify a token, and the algorithm it verified. */
export type KnownKid = { readonly alg: string; readonly learnedAtMs: number };
export type KnownKids = ReadonlyMap<string, KnownKid>;

export type SessionClass =
  /** No session cookie at all: the library finds no session and makes no call. */
  | { readonly kind: 'none' }
  /**
   * The token verifies with a signing key the library already holds: no call to Auth. `kid` and
   * `alg` are the ones the verification will use.
   */
  | { readonly kind: 'local'; readonly kid: string; readonly alg: string }
  /**
   * The library would fail on this session with an exception that is NOT an auth error (a decode
   * error, an unsupported algorithm, a key that cannot verify that algorithm), which would surface
   * as a 500 on every authenticated route, or with an auth error it can only reach locally. Either
   * way no call to Auth is made and the answer is 401: refused here, before the client runs.
   */
  | { readonly kind: 'refuse' }
  /**
   * Anything else: a refresh, a `getUser`, a JWKS fetch, or something this parse cannot rule out.
   * `kid`, when present, is the signing key the token claims (used to forget it when it fails).
   */
  | { readonly kind: 'upstream'; readonly kid?: string };

const UPSTREAM: SessionClass = { kind: 'upstream' };
const REFUSE: SessionClass = { kind: 'refuse' };

type Json = Record<string, unknown>;
const isObject = (value: unknown): value is Json => typeof value === 'object' && value !== null;

/** `JSON.parse(stringFromBase64URL(part))` as an object, or `undefined` if either step fails. */
function decodePart(part: string): Json | undefined {
  try {
    const value: unknown = JSON.parse(stringFromBase64URL(part));
    return isObject(value) ? value : undefined;
  } catch {
    return undefined;
  }
}

/** Steps 1 to 3: the session object the library would read from these cookies. */
async function readStoredSession(
  cookies: readonly SessionCookie[],
): Promise<{ present: false } | { present: true; session: unknown }> {
  const combined = await combineChunks(
    SESSION_COOKIE_NAME,
    (name) => cookies.find((cookie) => cookie.name === name)?.value ?? null,
  );
  if (!combined) return { present: false };
  // From here on a session cookie EXISTS: whatever it holds, never "no call" by omission.

  let json = combined;
  if (combined.startsWith(BASE64_PREFIX)) {
    try {
      json = stringFromBase64URL(combined.substring(BASE64_PREFIX.length));
      JSON.parse(json);
    } catch {
      return { present: true, session: undefined };
    }
  }
  try {
    return { present: true, session: JSON.parse(json) as unknown };
  } catch {
    return { present: true, session: undefined };
  }
}

export async function classifySession(
  cookies: readonly SessionCookie[],
  nowMs: number,
  knownKids: KnownKids,
): Promise<SessionClass> {
  const stored = await readStoredSession(cookies);
  if (!stored.present) return { kind: 'none' };

  // 4. `_isValidSession`. An invalid one is dropped by the library without a call, but a cookie that
  // is there and unreadable is charged all the same: that costs only whoever forged it.
  const { session } = stored;
  if (
    !isObject(session) ||
    !('access_token' in session) ||
    !('refresh_token' in session) ||
    !('expires_at' in session)
  ) {
    return UPSTREAM;
  }

  // 5. `hasExpired`, with the same truthiness and coercion. A refresh is a call to Auth, whatever
  // the token looks like and whatever type `expires_at` has.
  const expiresAt = session['expires_at'] as number;
  if (expiresAt ? expiresAt * MS_PER_SECOND - nowMs < REFRESH_MARGIN_MS : false) return UPSTREAM;

  // 6. `getClaims` on the token as it is.
  const token = session['access_token'];
  if (typeof token !== 'string') return REFUSE; // `token.split` would throw a TypeError

  const parts = token.split('.');
  if (parts.length !== JWT_PARTS || !parts.every((part) => BASE64URL_REGEX.test(part))) {
    return REFUSE; // AuthInvalidJwtError, reached without a call
  }
  const header = decodePart(parts[0] ?? '');
  const payload = decodePart(parts[1] ?? '');
  if (header === undefined || payload === undefined) return REFUSE; // SyntaxError / TypeError

  // `validateExp`: a missing, zero or past `exp` is an AuthInvalidJwtError before any call. An `exp`
  // of another type is not mirrored (it coerces); it falls through and is charged.
  const exp = payload['exp'];
  if (!exp || (typeof exp === 'number' && exp <= Math.floor(nowMs / MS_PER_SECOND))) return REFUSE;

  const alg = header['alg'];
  if (typeof alg !== 'string' || alg === '') return REFUSE; // falsy: invalid; truthy non-string: TypeError
  if (alg.startsWith('HS')) return UPSTREAM; // symmetric: checked by the Auth server (`getUser`)
  if (!SUPPORTED_ASYMMETRIC_ALGS.has(alg)) return REFUSE; // `getAlgorithm` would throw an Error

  const kid = header['kid'];
  if (typeof kid !== 'string' || kid === '') return UPSTREAM; // no kid: `getUser`

  const known = knownKids.get(kid);
  if (known === undefined || nowMs - known.learnedAtMs >= KID_FRESH_MS) {
    return { kind: 'upstream', kid }; // unknown or possibly evicted from the key cache: a JWKS fetch
  }
  // The key is one of this project's, and it verified `known.alg`: asking it to verify another
  // algorithm makes `importKey` throw a DOMException (a 500), so that token is refused here.
  if (known.alg !== alg) return REFUSE;
  return { kind: 'local', kid, alg };
}

/**
 * Would the session cookies make the server call the Auth server, or are they one the answer cannot
 * rule out? `false` only for "no session cookie" and for a token that positively verifies with a
 * signing key the library already holds; `true` for everything else, including the sessions that
 * `classifySession` refuses (they never reach Auth either, but they are not provably local).
 */
export async function needsAuthServer(
  cookies: readonly SessionCookie[],
  nowMs: number,
  knownKids: KnownKids,
): Promise<boolean> {
  const { kind } = await classifySession(cookies, nowMs, knownKids);
  return kind !== 'none' && kind !== 'local';
}
