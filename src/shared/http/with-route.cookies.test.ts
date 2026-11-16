import { describe, expect, it } from 'vitest';
import { NotFoundError } from '@/shared/kernel';
import { createCookieJar } from './cookies';
import { json } from './responses';
import {
  apiRequest,
  CEO_POLICY,
  createTestPipeline,
  principalFixture,
  PUBLIC_POLICY,
} from './testing';

const SESSION_COOKIE = '__Host-rt-session';

function cookieNamed(response: Response, name: string): string | undefined {
  return response.headers.getSetCookie().find((cookie) => cookie.startsWith(`${name}=`));
}

describe('createCookieJar', () => {
  it('reads the incoming cookies and sees its own writes and deletes', () => {
    const jar = createCookieJar([
      { name: 'a', value: '1' },
      { name: 'b', value: '2' },
    ]);
    expect(jar.get('a')).toBe('1');
    jar.set('a', 'new');
    jar.delete('b');
    jar.set('c', '3');
    expect(jar.get('a')).toBe('new');
    expect(jar.get('b')).toBeUndefined();
    expect(jar.getAll()).toEqual([
      { name: 'a', value: 'new' },
      { name: 'c', value: '3' },
    ]);
  });

  it('forces HttpOnly, Secure, SameSite=Lax and Path=/ on every cookie it writes', () => {
    const jar = createCookieJar([]);
    jar.set(SESSION_COOKIE, 'token', { maxAge: 3600 });
    const headers = new Headers();
    jar.applyTo(headers);
    const [cookie] = headers.getSetCookie();
    expect(cookie).toMatch(/^__Host-rt-session=token;/);
    expect(cookie).toMatch(/;\s*Path=\/(;|$)/i);
    expect(cookie).toMatch(/;\s*Secure(;|$)/i);
    expect(cookie).toMatch(/;\s*HttpOnly(;|$)/i);
    expect(cookie).toMatch(/;\s*SameSite=lax(;|$)/i);
    expect(cookie).toMatch(/Max-Age=3600/i);
    expect(cookie).not.toMatch(/Domain=/i);
  });

  it('SEC-07: an option outside the allow-list (a Domain) never reaches the header', () => {
    const jar = createCookieJar([]);
    // a JavaScript caller (or a future field) past the types
    jar.set(SESSION_COOKIE, 'token', {
      maxAge: 60,
      domain: 'evil.example',
      path: '/admin',
      sameSite: 'none',
    } as never);
    const headers = new Headers();
    jar.applyTo(headers);
    const [cookie] = headers.getSetCookie();
    expect(cookie).not.toMatch(/Domain=/i);
    expect(cookie).toMatch(/;\s*Path=\/(;|$)/i);
    expect(cookie).toMatch(/;\s*SameSite=lax(;|$)/i);
    expect(cookie).toMatch(/Max-Age=60/i);
  });

  it('expires a deleted cookie', () => {
    const jar = createCookieJar([{ name: SESSION_COOKIE, value: 'old' }]);
    jar.delete(SESSION_COOKIE);
    const headers = new Headers();
    jar.applyTo(headers);
    const [cookie] = headers.getSetCookie();
    expect(cookie).toMatch(/^__Host-rt-session=;/);
    expect(cookie).toMatch(/Max-Age=0/i);
    expect(cookie).toMatch(/Expires=Thu, 01 Jan 1970/i);
  });

  it('encodes values so they cannot inject attributes or extra cookies', () => {
    const jar = createCookieJar([]);
    jar.set('x', 'v; Domain=evil.test; Path=/admin');
    const headers = new Headers();
    jar.applyTo(headers);
    const [cookie] = headers.getSetCookie();
    expect(cookie).not.toMatch(/Domain=evil/i);
    expect(cookie).not.toContain('/admin');
    expect(headers.getSetCookie()).toHaveLength(1);
  });

  it('writes nothing when nothing was set', () => {
    const headers = new Headers();
    createCookieJar([{ name: 'a', value: '1' }]).applyTo(headers);
    expect(headers.getSetCookie()).toEqual([]);
  });

  it('writes one header per cookie, keeping the chunked session cookies (.0, .1)', () => {
    const jar = createCookieJar([]);
    jar.set(`${SESSION_COOKIE}.0`, 'chunk-a');
    jar.set(`${SESSION_COOKIE}.1`, 'chunk-b');
    const headers = new Headers();
    jar.applyTo(headers);
    expect(headers.getSetCookie()).toHaveLength(2);
  });
});

describe('withRoute: cookie jar in the handler context', () => {
  it('applies the cookies a handler writes to the success response', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, ({ cookies }) => {
      cookies.set(SESSION_COOKIE, 'session-token');
      return json(200, {});
    });
    const response = await route(apiRequest('/x'));
    const cookie = cookieNamed(response, SESSION_COOKIE);
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/Secure/i);
    expect(cookie).toMatch(/SameSite=lax/i);
    expect(cookie).toMatch(/Path=\//i);
  });

  it('applies them to error responses too: a returned DomainError', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, ({ cookies }) => {
      cookies.delete(SESSION_COOKIE);
      return new NotFoundError('gone');
    });
    const response = await route(apiRequest('/x'));
    expect(response.status).toBe(404);
    expect(cookieNamed(response, SESSION_COOKIE)).toMatch(/Max-Age=0/i);
  });

  it('applies them to error responses too: a thrown exception (500)', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, ({ cookies }) => {
      cookies.set(SESSION_COOKIE, 'half-done');
      throw new Error('boom');
    });
    const response = await route(apiRequest('/x'));
    expect(response.status).toBe(500);
    expect(cookieNamed(response, SESSION_COOKIE)).toBeDefined();
  });

  it('keeps cookies the principal resolver refreshed even when the request is then denied', async () => {
    const { withRoute } = createTestPipeline({
      principal: ({ cookies }) => {
        cookies.set(SESSION_COOKIE, 'rotated-refresh-token');
        return principalFixture({ role: 'client', clientId: 'c1' });
      },
    });
    const route = withRoute(CEO_POLICY, () => json(200, {}));
    const response = await route(apiRequest('/x'));
    expect(response.status).toBe(403);
    expect(cookieNamed(response, SESSION_COOKIE)).toContain('rotated-refresh-token');
  });

  it('keeps them when the resolver finds no session (e.g. it clears a dead cookie)', async () => {
    const { withRoute } = createTestPipeline({
      principal: ({ cookies }) => {
        cookies.delete(SESSION_COOKIE);
        return null;
      },
    });
    const route = withRoute(CEO_POLICY, () => json(200, {}));
    const response = await route(
      apiRequest('/x', { headers: { cookie: `${SESSION_COOKIE}=dead` } }),
    );
    expect(response.status).toBe(401);
    expect(cookieNamed(response, SESSION_COOKIE)).toMatch(/Max-Age=0/i);
  });

  it('exposes the request cookies to the resolver and the handler', async () => {
    const seen: string[] = [];
    const { withRoute } = createTestPipeline({
      principal: ({ cookies }) => {
        seen.push(`resolver:${cookies.get(SESSION_COOKIE)}`);
        return principalFixture();
      },
    });
    const route = withRoute(CEO_POLICY, ({ cookies }) => {
      seen.push(`handler:${cookies.get(SESSION_COOKIE)}`);
      return json(200, {});
    });
    await route(apiRequest('/x', { headers: { cookie: `${SESSION_COOKIE}=abc; other=1` } }));
    expect(seen).toEqual(['resolver:abc', 'handler:abc']);
  });

  it('does not leak cookies between requests', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, ({ cookies, request }) => {
      if (request.nextUrl.pathname.endsWith('/first')) cookies.set('only-first', '1');
      return json(200, {});
    });
    const first = await route(apiRequest('/first'));
    const second = await route(apiRequest('/second'));
    expect(cookieNamed(first, 'only-first')).toBeDefined();
    expect(second.headers.getSetCookie()).toEqual([]);
  });
});
