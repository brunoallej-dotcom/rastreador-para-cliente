import { describe, expect, it } from 'vitest';
import { needsAuthServer } from './needs-auth-server';

const NOW_MS = Date.parse('2026-11-16T12:00:00Z');
const NOW_S = NOW_MS / 1000;
const HOUR_S = 3600;

const b64url = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
const jwt = (header: Record<string, unknown>) =>
  `${b64url(header)}.${b64url({ sub: 'x' })}.signature`;
const cookies = (session: Record<string, unknown>) => [
  { name: '__Host-rt-session', value: `base64-${b64url(session)}` },
];
const session = (accessToken: string, expiresAt: number) =>
  cookies({ access_token: accessToken, refresh_token: 'r', expires_at: expiresAt });

const ES256_KNOWN = jwt({ alg: 'ES256', kid: 'key-1', typ: 'JWT' });
const known = new Set(['key-1']);

describe('needsAuthServer: what a session cookie would make the server do', () => {
  it('F-01: no cookie, or one that is not a session, costs no call to Auth', () => {
    expect(needsAuthServer([], NOW_MS, known)).toBe(false);
    expect(needsAuthServer([{ name: '__Host-rt-session', value: 'garbage' }], NOW_MS, known)).toBe(
      false,
    );
    expect(needsAuthServer(cookies({ access_token: 'x' }), NOW_MS, known)).toBe(false);
    expect(
      needsAuthServer(
        cookies({ access_token: 'x', refresh_token: 'y', expires_at: 'soon' }),
        NOW_MS,
        known,
      ),
    ).toBe(false);
  });

  it('F-01: an unexpired access token that is not a JWT is dropped by the client without a call', () => {
    expect(needsAuthServer(session('x', NOW_S + HOUR_S), NOW_MS, known)).toBe(false);
    expect(needsAuthServer(session('a.b', NOW_S + HOUR_S), NOW_MS, known)).toBe(false);
    expect(needsAuthServer(session('@@@.b.c', NOW_S + HOUR_S), NOW_MS, known)).toBe(false);
  });

  it('F-01: an expired (or about to expire) access token is refreshed: a call to Auth', () => {
    expect(needsAuthServer(session(ES256_KNOWN, 1), NOW_MS, known)).toBe(true);
    expect(needsAuthServer(session(ES256_KNOWN, NOW_S + 30), NOW_MS, known)).toBe(true);
    // the cookie's own expiry is what decides, however forged
    expect(needsAuthServer(session(jwt({}), 1), NOW_MS, known)).toBe(true);
    // the forged cookie of the finding: the refresh does not look at the token
    expect(needsAuthServer(session('x', 1), NOW_MS, known)).toBe(true);
  });

  it('F-01: a token the server cannot verify locally is a call to Auth', () => {
    for (const header of [
      { alg: 'HS256', typ: 'JWT' },
      { alg: 'HS512', kid: 'key-1' },
      { alg: 'ES256' }, // no kid
      { alg: 'ES256', kid: '' },
      { kid: 'key-1' }, // no alg
      { alg: 'ES256', kid: 'never-seen' }, // unknown kid: a JWKS fetch
      {},
    ]) {
      expect(
        needsAuthServer(session(jwt(header), NOW_S + HOUR_S), NOW_MS, known),
        JSON.stringify(header),
      ).toBe(true);
    }
  });

  it('an asymmetric token with a kid that already verified a token here is checked locally', () => {
    expect(needsAuthServer(session(ES256_KNOWN, NOW_S + HOUR_S), NOW_MS, known)).toBe(false);
    expect(needsAuthServer(session(ES256_KNOWN, NOW_S + HOUR_S), NOW_MS, new Set())).toBe(true);
  });

  it('reads chunked cookies too', () => {
    const value = `base64-${b64url({ access_token: jwt({ alg: 'HS256' }), refresh_token: 'r', expires_at: NOW_S + HOUR_S })}`;
    const half = Math.ceil(value.length / 2);
    expect(
      needsAuthServer(
        [
          { name: '__Host-rt-session.1', value: value.slice(half) },
          { name: '__Host-rt-session.0', value: value.slice(0, half) },
        ],
        NOW_MS,
        known,
      ),
    ).toBe(true);
  });
});
