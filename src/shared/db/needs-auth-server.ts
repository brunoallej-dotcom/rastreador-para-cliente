import { readSession, type SessionCookie } from './session-cookies';

/**
 * How close to its expiry the Auth client refreshes an access token: 90 s, the client library's
 * own margin (`EXPIRY_MARGIN_MS` of auth-js). The cookie decides it with its `expires_at`, which
 * anybody can forge.
 */
const REFRESH_MARGIN_MS = 90_000;

const JWT_PARTS = 3;

/** The JOSE header of a token, `undefined` when the first part is not base64url JSON. */
function decodeHeader(token: string): { alg?: unknown; kid?: unknown } | undefined {
  const parts = token.split('.');
  if (parts.length !== JWT_PARTS) return undefined;
  try {
    const header: unknown = JSON.parse(Buffer.from(parts[0] ?? '', 'base64url').toString('utf8'));
    return typeof header === 'object' && header !== null ? header : {};
  } catch {
    return undefined;
  }
}

/** `alg` values the Auth client verifies with the secret it shares with the Auth server. */
const isSymmetric = (alg: unknown): boolean => typeof alg !== 'string' || alg.startsWith('HS');

/**
 * Would handing these session cookies to the Auth client make the server call the Auth server?
 * The answer is worked out WITHOUT trusting the cookie (it is attacker-controlled), mirroring what
 * the client library does:
 *
 * - no session, or a malformed one: the library drops it and makes no call, so nothing is spent;
 * - an access token at or past its expiry (by the cookie's own `expires_at`): the library refreshes
 *   it, a call to the Auth server, whatever the token looks like;
 * - an unexpired access token that is not a JWT: dropped without a call;
 * - an access token it cannot verify locally, that is a symmetric algorithm (HS256, the local
 *   stack), no `kid`, or a `kid` the process has not yet seen verify a token: a call to the Auth
 *   server (`getUser`, or a JWKS fetch);
 * - an asymmetric token with a `kid` that already verified a token here: checked locally.
 *
 * Every "yes" is something a forged cookie can cause from a single IP, with nothing in front of it
 * but this answer: the caller spends a per-IP budget before it lets the call happen (F-01).
 */
export function needsAuthServer(
  cookies: readonly SessionCookie[],
  nowMs: number,
  knownKids: ReadonlySet<string>,
): boolean {
  const session = readSession(cookies);
  if (session === undefined) return false;

  // The refresh comes first: the client library decides it from the cookie's `expires_at` before
  // it looks at the token at all, so even `{"access_token":"x","refresh_token":"y","expires_at":1}`
  // makes the server call the Auth server.
  if (session.expiresAt * 1000 - nowMs < REFRESH_MARGIN_MS) return true;

  const header = decodeHeader(session.accessToken);
  if (header === undefined) return false;

  if (isSymmetric(header.alg)) return true;
  return typeof header.kid !== 'string' || header.kid === '' || !knownKids.has(header.kid);
}
