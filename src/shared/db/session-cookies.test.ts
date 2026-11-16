import { describe, expect, it } from 'vitest';
import { createCookieJar } from '@/shared/http/cookies';
import {
  isSessionCookieName,
  readAccessToken,
  restoreSessionCookies,
  SESSION_COOKIE_NAME,
  snapshotSessionCookies,
} from './session-cookies';

describe('isSessionCookieName', () => {
  it('matches the session cookie and its chunks, and nothing else', () => {
    expect(isSessionCookieName('__Host-rt-session')).toBe(true);
    expect(isSessionCookieName('__Host-rt-session.0')).toBe(true);
    expect(isSessionCookieName('__Host-rt-session.12')).toBe(true);
    expect(isSessionCookieName('__Host-rt-sessionX')).toBe(false);
    expect(isSessionCookieName('other')).toBe(false);
    expect(isSessionCookieName('sb-session')).toBe(false);
  });
});

describe('snapshot and restore of the session cookies', () => {
  it('SEC-07: the cookie name carries the __Host- prefix', () => {
    expect(SESSION_COOKIE_NAME).toBe('__Host-rt-session');
  });

  it('puts back a session that a failed sign-out had already cleared', () => {
    const jar = createCookieJar([
      { name: '__Host-rt-session.0', value: 'chunk-0' },
      { name: '__Host-rt-session.1', value: 'chunk-1' },
      { name: 'unrelated', value: 'x' },
    ]);
    const snapshot = snapshotSessionCookies(jar);
    expect(snapshot.map(({ name }) => name)).toEqual([
      '__Host-rt-session.0',
      '__Host-rt-session.1',
    ]);

    jar.delete('__Host-rt-session.0');
    jar.delete('__Host-rt-session.1');
    expect(snapshotSessionCookies(jar)).toEqual([]);

    restoreSessionCookies(jar, snapshot);
    expect(jar.get('__Host-rt-session.0')).toBe('chunk-0');
    expect(jar.get('__Host-rt-session.1')).toBe('chunk-1');
    const headers = new Headers();
    jar.applyTo(headers);
    const written = headers.getSetCookie();
    expect(written).toHaveLength(2);
    for (const cookie of written) expect(cookie).not.toMatch(/Max-Age=0/i);
    expect(jar.get('unrelated')).toBe('x');
  });

  it('removes session cookies that were not in the snapshot', () => {
    const jar = createCookieJar([{ name: '__Host-rt-session', value: 'a' }]);
    const snapshot = snapshotSessionCookies(jar);
    jar.set('__Host-rt-session.0', 'late');
    restoreSessionCookies(jar, snapshot);
    expect(jar.get('__Host-rt-session')).toBe('a');
    expect(jar.get('__Host-rt-session.0')).toBeUndefined();
  });
});

describe('readAccessToken', () => {
  const encode = (session: unknown) =>
    `base64-${Buffer.from(JSON.stringify(session), 'utf8').toString('base64url')}`;

  it('reads the token of a single cookie', () => {
    const value = encode({ access_token: 'the-token', refresh_token: 'r' });
    expect(readAccessToken([{ name: '__Host-rt-session', value }])).toBe('the-token');
  });

  it('joins chunks in numeric order, not in the order they come', () => {
    const value = encode({ access_token: 'the-token', padding: 'x'.repeat(40) });
    const third = Math.ceil(value.length / 3);
    const chunks = [
      { name: '__Host-rt-session.10', value: value.slice(third * 2) },
      { name: '__Host-rt-session.2', value: value.slice(third, third * 2) },
      { name: '__Host-rt-session.1', value: value.slice(0, third) },
    ];
    // .1 < .2 < .10 numerically, although ".10" sorts before ".2" as text
    expect(readAccessToken(chunks)).toBe('the-token');
  });

  it.each([
    ['no session cookie', []],
    ['an unrelated cookie', [{ name: 'other', value: encode({ access_token: 't' }) }]],
    ['a value without the base64- prefix', [{ name: '__Host-rt-session', value: 'plain' }]],
    ['a value that is not base64 JSON', [{ name: '__Host-rt-session', value: 'base64-@@@' }]],
    ['a session without an access token', [{ name: '__Host-rt-session', value: encode({}) }]],
    [
      'an access token that is not a string',
      [{ name: '__Host-rt-session', value: encode({ access_token: 5 }) }],
    ],
    ['a JSON null', [{ name: '__Host-rt-session', value: encode(null) }]],
  ])('is undefined for %s', (_label, cookies) => {
    expect(readAccessToken(cookies)).toBeUndefined();
  });
});
