import { describe, expect, it } from 'vitest';
import { clientIp } from './client-ip';
import { json, noContent } from './responses';
import { routeTemplate } from './route-template';
import { SECURITY_HEADERS, withSecurityHeaders } from './security-headers';
import { resolveRequestId } from './request-id';

describe('withSecurityHeaders', () => {
  it('sets every SEC-14 header and X-Request-Id, overriding the handler', async () => {
    const original = json(
      201,
      { id: 1 },
      { headers: { 'Cache-Control': 'public', Location: '/x/1' } },
    );
    const secured = withSecurityHeaders(original, 'req-12345678');
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      expect(secured.headers.get(name)).toBe(value);
    }
    expect(secured.headers.get('x-request-id')).toBe('req-12345678');
    expect(secured.headers.get('location')).toBe('/x/1');
    expect(secured.status).toBe(201);
    expect(await secured.json()).toEqual({ id: 1 });
  });

  it('works on a Response whose headers are immutable (e.g. a redirect)', () => {
    const secured = withSecurityHeaders(
      Response.redirect('https://app.example.com/', 302),
      'req-12345678',
    );
    expect(secured.status).toBe(302);
    expect(secured.headers.get('x-frame-options')).toBe('DENY');
  });

  it('keeps an empty body empty (204)', () => {
    const secured = withSecurityHeaders(noContent(), 'req-12345678');
    expect(secured.status).toBe(204);
    expect(secured.body).toBeNull();
  });

  it('never adds CORS headers or X-Powered-By', () => {
    const secured = withSecurityHeaders(json(200, {}), 'req-12345678');
    expect(secured.headers.get('access-control-allow-origin')).toBeNull();
    expect(secured.headers.get('x-powered-by')).toBeNull();
  });
});

describe('json and noContent', () => {
  it('json sets the content type and serializes the body', async () => {
    const response = json(200, { status: 'ok' });
    expect(response.headers.get('content-type')).toBe('application/json');
    expect(await response.json()).toEqual({ status: 'ok' });
  });

  it('json lets the caller add headers such as Location', () => {
    expect(json(201, {}, { headers: { Location: '/a/1' } }).headers.get('location')).toBe('/a/1');
  });

  it('noContent is a 204 without body', () => {
    const response = noContent();
    expect(response.status).toBe(204);
    expect(response.body).toBeNull();
  });
});

describe('clientIp', () => {
  const request = (headers: Record<string, string>) => new Request('https://x.test/', { headers });

  it('reads the platform header only', () => {
    expect(clientIp(request({ 'x-real-ip': '203.0.113.5' }))).toBe('203.0.113.5');
    expect(clientIp(request({ 'x-forwarded-for': '198.51.100.1' }))).toBeUndefined();
    expect(
      clientIp(request({ 'x-client-ip': '198.51.100.1', 'cf-connecting-ip': '198.51.100.2' })),
    ).toBeUndefined();
  });

  it('has no subject when there is no IP, or it is not an IP', () => {
    expect(clientIp(request({}))).toBeUndefined();
    expect(clientIp(request({ 'x-real-ip': 'a'.repeat(200) }))).toBeUndefined();
  });
});

describe('routeTemplate', () => {
  it('replaces path param values with their names', () => {
    expect(
      routeTemplate('/api/v1/admin/clients/c-1/users/u-2', { clientId: 'c-1', userId: 'u-2' }),
    ).toBe('/api/v1/admin/clients/[clientId]/users/[userId]');
  });

  it('leaves static paths alone', () => {
    expect(routeTemplate('/api/v1/health', {})).toBe('/api/v1/health');
  });

  it('matches percent-encoded segments by their decoded value', () => {
    expect(routeTemplate('/api/v1/x/a%20b', { name: 'a b' })).toBe('/api/v1/x/[name]');
  });
});

describe('resolveRequestId', () => {
  it('accepts 8 to 64 characters of [A-Za-z0-9-]', () => {
    expect(resolveRequestId('abcd1234')).toBe('abcd1234');
    expect(resolveRequestId('a'.repeat(64))).toBe('a'.repeat(64));
    expect(resolveRequestId('3f2504e0-4f89-41d3-9a0c-0305e82c3301')).toBe(
      '3f2504e0-4f89-41d3-9a0c-0305e82c3301',
    );
  });

  it.each([null, '', 'short', 'a'.repeat(65), 'has space1', 'under_score', 'unicode-é-123456'])(
    'replaces %j with a fresh UUID',
    (incoming) => {
      expect(resolveRequestId(incoming)).toMatch(/^[0-9a-f-]{36}$/);
    },
  );
});
