import type { CookieJar } from '@/shared/http/cookies';

/** The session cookie of `@supabase/ssr`; the `__Host-` prefix needs Secure, Path=/ and no Domain. */
export const SESSION_COOKIE_NAME = '__Host-rt-session';
const SECONDS_PER_DAY = 24 * 60 * 60;
/** Lifetime of the cookie (the default of `@supabase/ssr`); the session itself lives in Supabase. */
export const SESSION_COOKIE_MAX_AGE_SECONDS = 400 * SECONDS_PER_DAY;

export type SessionCookie = { readonly name: string; readonly value: string };

/** `__Host-rt-session` and its chunks `__Host-rt-session.0`, `.1`... */
export function isSessionCookieName(name: string): boolean {
  return name === SESSION_COOKIE_NAME || name.startsWith(`${SESSION_COOKIE_NAME}.`);
}

/** The session cookies (and chunks) the jar holds right now. */
export function snapshotSessionCookies(jar: CookieJar): SessionCookie[] {
  return jar.getAll().filter(({ name }) => isSessionCookieName(name));
}

/**
 * Puts a snapshot back: every cookie of the snapshot is written again, and any session cookie that
 * is not in the snapshot is deleted. Used when a call that clears the session did not complete, so
 * the browser keeps a session it can still use to try again.
 */
export function restoreSessionCookies(jar: CookieJar, snapshot: readonly SessionCookie[]): void {
  const kept = new Set(snapshot.map(({ name }) => name));
  for (const { name, value } of snapshot) {
    jar.set(name, value, { maxAge: SESSION_COOKIE_MAX_AGE_SECONDS });
  }
  for (const { name } of jar.getAll()) {
    if (isSessionCookieName(name) && !kept.has(name)) jar.delete(name);
  }
}

const BASE64_PREFIX = 'base64-';

const chunkIndex = (name: string): number => Number(name.slice(SESSION_COOKIE_NAME.length + 1));

/**
 * The access token inside the session cookies (`@supabase/ssr` stores `base64-` + base64url of the
 * session JSON, split in chunks `.0`, `.1`... when large), or `undefined` when they hold none.
 * It is read from an UNVERIFIED cookie and is meant only to be shown to the database, which
 * verifies it: logout uses it to confirm that the session really died.
 */
export function readAccessToken(cookies: readonly SessionCookie[]): string | undefined {
  const whole = cookies.find(({ name }) => name === SESSION_COOKIE_NAME);
  const encoded =
    whole?.value ??
    cookies
      .filter(({ name }) => name.startsWith(`${SESSION_COOKIE_NAME}.`))
      .sort((a, b) => chunkIndex(a.name) - chunkIndex(b.name))
      .map(({ value }) => value)
      .join('');
  if (!encoded.startsWith(BASE64_PREFIX)) return undefined;

  try {
    const session: unknown = JSON.parse(
      Buffer.from(encoded.slice(BASE64_PREFIX.length), 'base64url').toString('utf8'),
    );
    const token = (session as { access_token?: unknown } | null)?.access_token;
    return typeof token === 'string' && token !== '' ? token : undefined;
  } catch {
    return undefined;
  }
}
