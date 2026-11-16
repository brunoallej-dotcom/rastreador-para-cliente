import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { NotFoundError, ServiceUnavailableError, type Principal } from '@/shared/kernel';
import { getFallbackLogger } from '@/shared/observability/logger';
import { MAX_BODY_BYTES } from './body';
import { createFakePrincipalResolver } from './fake-principal-resolver';
import { createInMemoryRateLimiter } from './rate-limit/in-memory-rate-limiter';
import type { RateLimiter } from './rate-limit/rate-limiter';
import { json } from './responses';
import {
  apiRequest,
  CEO_POLICY,
  createTestPipeline,
  principalFixture,
  PUBLIC_POLICY,
  TEST_APP_ORIGIN,
} from './testing';
import { createWithRoute } from './with-route';

/** SEC-14, written out independently of the implementation's constant. */
const SEC14_HEADERS = {
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
} as const;

const REQUEST_ID_PATTERN = /^[A-Za-z0-9-]{8,64}$/;
/** Anything that would leak internals: stack frames, SQL, file paths, the thrown message. */
const LEAK_PATTERN = /stack|\bat\s+\S+\s+\(|\.tsx?:\d+|SELECT|INSERT|auth\.users|secret_table/i;

function expectSecurityEnvelope(response: Response) {
  for (const [name, value] of Object.entries(SEC14_HEADERS)) {
    expect(response.headers.get(name), name).toBe(value);
  }
  expect(response.headers.get('permissions-policy')).toBeTruthy();
  expect(response.headers.get('x-request-id')).toMatch(REQUEST_ID_PATTERN);
  expect(response.headers.get('x-powered-by')).toBeNull();
  for (const [name] of response.headers) expect(name.startsWith('access-control-')).toBe(false);
}

async function expectProblem(response: Response, status: number, code: string) {
  expect(response.status).toBe(status);
  expect(response.headers.get('content-type')).toBe('application/problem+json');
  const text = await response.text();
  expect(text).not.toMatch(LEAK_PATTERN);
  const body = JSON.parse(text) as Record<string, unknown>;
  expect(body).toMatchObject({ type: 'about:blank', status, code });
  expect(typeof body['title']).toBe('string');
  expect(body['requestId']).toBe(response.headers.get('x-request-id'));
  return body;
}

const bodySchema = z.object({ name: z.string().min(1).max(50) }).strict();

describe('withRoute: security envelope on every response', () => {
  const failingLimiter: RateLimiter = {
    consume: () => Promise.reject(new Error('connection to secret_table store refused')),
  };

  const scenarios: {
    name: string;
    status: number;
    code?: string;
    run: () => Promise<Response>;
  }[] = [
    {
      name: '200 success',
      status: 200,
      run: () => {
        const { withRoute } = createTestPipeline();
        return withRoute(PUBLIC_POLICY, () => json(200, { status: 'ok' }))(apiRequest('/x'));
      },
    },
    {
      name: '401 without a session',
      status: 401,
      code: 'UNAUTHENTICATED',
      run: () => {
        const { withRoute } = createTestPipeline({ principal: null });
        return withRoute(CEO_POLICY, () => json(200, {}))(apiRequest('/x'));
      },
    },
    {
      name: '403 wrong role',
      status: 403,
      code: 'FORBIDDEN',
      run: () => {
        const { withRoute } = createTestPipeline({
          principal: principalFixture({ role: 'client', clientId: 'c1' }),
        });
        return withRoute(CEO_POLICY, () => json(200, {}))(apiRequest('/x'));
      },
    },
    {
      name: '403 origin not allowed',
      status: 403,
      code: 'ORIGIN_NOT_ALLOWED',
      run: () => {
        const { withRoute } = createTestPipeline();
        return withRoute({ ...PUBLIC_POLICY, body: bodySchema }, () => json(200, {}))(
          apiRequest('/x', { method: 'POST', json: { name: 'a' }, origin: 'https://evil.test' }),
        );
      },
    },
    {
      name: '400 validation error',
      status: 400,
      code: 'VALIDATION_ERROR',
      run: () => {
        const { withRoute } = createTestPipeline();
        return withRoute(
          { ...PUBLIC_POLICY, query: z.object({ page: z.string().regex(/^\d+$/) }).strict() },
          () => json(200, {}),
        )(apiRequest('/x?page=abc'));
      },
    },
    {
      name: '404 returned by the handler',
      status: 404,
      code: 'NOT_FOUND',
      run: () => {
        const { withRoute } = createTestPipeline();
        return withRoute(
          PUBLIC_POLICY,
          () => new NotFoundError('row 42 missing in secret_table (SELECT * FROM auth.users)'),
        )(apiRequest('/x'));
      },
    },
    {
      name: '415 wrong content type',
      status: 415,
      code: 'UNSUPPORTED_MEDIA_TYPE',
      run: () => {
        const { withRoute } = createTestPipeline();
        return withRoute({ ...PUBLIC_POLICY, body: bodySchema }, () => json(200, {}))(
          apiRequest('/x', {
            method: 'POST',
            body: 'name=a',
            headers: { 'content-type': 'text/plain' },
          }),
        );
      },
    },
    {
      name: '413 payload too large',
      status: 413,
      code: 'PAYLOAD_TOO_LARGE',
      run: () => {
        const { withRoute } = createTestPipeline();
        return withRoute({ ...PUBLIC_POLICY, body: bodySchema }, () => json(200, {}))(
          apiRequest('/x', { method: 'POST', json: { name: 'a'.repeat(MAX_BODY_BYTES) } }),
        );
      },
    },
    {
      name: '429 rate limited',
      status: 429,
      code: 'RATE_LIMITED',
      run: async () => {
        const { withRoute } = createTestPipeline();
        const route = withRoute(
          {
            ...PUBLIC_POLICY,
            rateLimit: [{ scope: 'ip', group: 'reads', limit: 1, windowSeconds: 60 }],
          },
          () => json(200, {}),
        );
        await route(apiRequest('/x'));
        return route(apiRequest('/x'));
      },
    },
    {
      name: '500 from a throwing handler',
      status: 500,
      code: 'INTERNAL_ERROR',
      run: () => {
        const { withRoute } = createTestPipeline();
        return withRoute(PUBLIC_POLICY, () => {
          throw new Error('SELECT * FROM auth.users failed at secret_table');
        })(apiRequest('/x'));
      },
    },
    {
      name: '503 when the rate limiter fails',
      status: 503,
      code: 'SERVICE_UNAVAILABLE',
      run: () => {
        const { withRoute } = createTestPipeline({ rateLimiter: failingLimiter });
        return withRoute(
          {
            ...PUBLIC_POLICY,
            rateLimit: [{ scope: 'ip', group: 'reads', limit: 1, windowSeconds: 60 }],
          },
          () => json(200, {}),
        )(apiRequest('/x'));
      },
    },
  ];

  it.each(scenarios)(
    'AC-22: $name carries the SEC-14 headers, X-Request-Id and no-store',
    async ({ status, code, run }) => {
      const response = await run();
      expectSecurityEnvelope(response);
      if (code === undefined) {
        expect(response.status).toBe(status);
        expect(response.headers.get('content-type')).toBe('application/json');
      } else {
        await expectProblem(response, status, code);
      }
    },
  );

  it('AC-22: a 500 from a throwing handler never exposes the stack, SQL or the thrown message', async () => {
    const { withRoute, logs } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, () => {
      throw new Error('SELECT * FROM auth.users failed at secret_table');
    });
    const response = await route(apiRequest('/x'));
    const text = await response.text();

    expect(text).not.toMatch(LEAK_PATTERN);
    expect(text).not.toContain('failed');
    // ...but the stack is in the logs, at error level, for the on-call engineer.
    const logged = logs.records().find((record) => record['level'] === 'error');
    expect(JSON.stringify(logged)).toContain('SELECT * FROM auth.users failed');
    expect(JSON.stringify(logged)).toContain('stack');
  });

  it('AC-22: a handler cannot remove or override the security headers', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, () =>
      json(
        200,
        {},
        { headers: { 'Cache-Control': 'public, max-age=3600', 'X-Frame-Options': 'ALLOWALL' } },
      ),
    );
    const response = await route(apiRequest('/x'));
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('x-frame-options')).toBe('DENY');
  });
});

describe('withRoute: request id', () => {
  const run = (headers: Record<string, string>) => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, ({ requestId }) => json(200, { requestId }));
    return route(apiRequest('/x', { headers }));
  };

  it('reuses a valid incoming X-Request-Id and exposes it to the handler', async () => {
    const response = await run({ 'x-request-id': 'client-trace-0001' });
    expect(response.headers.get('x-request-id')).toBe('client-trace-0001');
    expect(await response.json()).toEqual({ requestId: 'client-trace-0001' });
  });

  it.each([
    ['too short', 'abc'],
    ['too long', 'a'.repeat(65)],
    ['unsafe characters', 'id with spaces!'],
    ['header injection attempt', 'abcdefgh\r\nSet-Cookie: x=1'],
  ])('replaces an incoming id that is %s with a UUID v4', async (_label, incoming) => {
    const headers = new Headers();
    // `Headers` rejects CR/LF, so the injection case is sent without it.
    headers.set('x-request-id', incoming.replace(/[\r\n]/g, ''));
    const response = await run(Object.fromEntries(headers));
    expect(response.headers.get('x-request-id')).not.toBe(incoming);
    expect(response.headers.get('x-request-id')).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it('generates a different UUID for every request without an incoming id', async () => {
    const first = (await run({})).headers.get('x-request-id');
    const second = (await run({})).headers.get('x-request-id');
    expect(first).not.toBe(second);
  });
});

describe('withRoute: transport checks (Origin, Content-Type, size, body)', () => {
  const setup = () => {
    const handler = vi.fn(() => json(200, { ok: true }));
    const { withRoute, logs } = createTestPipeline();
    const route = withRoute({ ...PUBLIC_POLICY, body: bodySchema }, handler);
    return { route, handler, logs };
  };

  it('AC-23: POST without Origin → 403 ORIGIN_NOT_ALLOWED', async () => {
    const { route, handler } = setup();
    const response = await route(
      apiRequest('/x', { method: 'POST', json: { name: 'a' }, origin: null }),
    );
    await expectProblem(response, 403, 'ORIGIN_NOT_ALLOWED');
    expect(handler).not.toHaveBeenCalled();
  });

  it.each([
    'https://evil.test',
    'null',
    'http://localhost:3000.evil.test',
    'https://localhost:3000',
    'http://localhost:3000/',
    'HTTP://LOCALHOST:3000',
  ])('AC-23: POST with Origin %s → 403 ORIGIN_NOT_ALLOWED', async (origin) => {
    const { route, handler } = setup();
    const response = await route(apiRequest('/x', { method: 'POST', json: { name: 'a' }, origin }));
    await expectProblem(response, 403, 'ORIGIN_NOT_ALLOWED');
    expect(handler).not.toHaveBeenCalled();
  });

  it.each(['POST', 'PUT', 'PATCH', 'DELETE'])(
    'AC-23: %s needs an allowed Origin',
    async (method) => {
      const { withRoute } = createTestPipeline();
      const route = withRoute(PUBLIC_POLICY, () => json(200, {}));
      const denied = await route(apiRequest('/x', { method, origin: null }));
      await expectProblem(denied, 403, 'ORIGIN_NOT_ALLOWED');
      const allowed = await route(apiRequest('/x', { method }));
      expect(allowed.status).toBe(200);
    },
  );

  it('safe methods do not need an Origin', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, () => json(200, {}));
    expect((await route(apiRequest('/x'))).status).toBe(200);
  });

  it('accepts every allowed origin (preview deployments add their own URLs)', async () => {
    const allowed = ['https://app.example.com', 'https://app-abc123.vercel.app'];
    const { withRoute } = createTestPipeline({ allowedOrigins: allowed });
    const route = withRoute(PUBLIC_POLICY, () => json(200, {}));
    for (const origin of allowed) {
      expect((await route(apiRequest('/x', { method: 'POST', origin }))).status).toBe(200);
    }
    const denied = await route(
      apiRequest('/x', { method: 'POST', origin: 'http://localhost:3000' }),
    );
    expect(denied.status).toBe(403);
  });

  it.each([
    ['text/plain', 'name=a'],
    ['application/x-www-form-urlencoded', 'name=a'],
    ['multipart/form-data; boundary=x', '--x--'],
    ['application/jsonp', '{"name":"a"}'],
    ['application/json; charset=iso-8859-1', '{"name":"a"}'],
  ])('AC-23: Content-Type %s → 415 UNSUPPORTED_MEDIA_TYPE', async (contentType, body) => {
    const { route, handler } = setup();
    const response = await route(
      apiRequest('/x', { method: 'POST', body, headers: { 'content-type': contentType } }),
    );
    await expectProblem(response, 415, 'UNSUPPORTED_MEDIA_TYPE');
    expect(handler).not.toHaveBeenCalled();
  });

  it('AC-23: a non-empty body without Content-Type → 415', async () => {
    const { route } = setup();
    const response = await route(
      apiRequest('/x', { method: 'POST', body: '{"name":"a"}', headers: { 'content-type': '' } }),
    );
    expect(response.status).toBe(415);
  });

  it.each([
    'application/json',
    'application/json; charset=utf-8',
    'Application/JSON;Charset="UTF-8"',
  ])('accepts Content-Type %s', async (contentType) => {
    const { route } = setup();
    const response = await route(
      apiRequest('/x', {
        method: 'POST',
        body: '{"name":"a"}',
        headers: { 'content-type': contentType },
      }),
    );
    expect(response.status).toBe(200);
  });

  it('AC-23: a body above 16 KiB → 413 PAYLOAD_TOO_LARGE', async () => {
    const { route, handler } = setup();
    const response = await route(
      apiRequest('/x', { method: 'POST', json: { name: 'a'.repeat(MAX_BODY_BYTES) } }),
    );
    await expectProblem(response, 413, 'PAYLOAD_TOO_LARGE');
    expect(handler).not.toHaveBeenCalled();
  });

  it('AC-23: a body above 16 KiB is rejected even with a lying Content-Length', async () => {
    const { route, handler } = setup();
    const response = await route(
      apiRequest('/x', {
        method: 'POST',
        json: { name: 'a'.repeat(MAX_BODY_BYTES) },
        headers: { 'content-length': '12' },
      }),
    );
    await expectProblem(response, 413, 'PAYLOAD_TOO_LARGE');
    expect(handler).not.toHaveBeenCalled();
  });

  it('AC-23: a declared Content-Length above the limit is rejected without reading the body', async () => {
    const { route } = setup();
    let pulled = 0;
    // highWaterMark 0: the stream does not pull ahead on its own, only when someone reads it.
    const stream = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          pulled += 1;
          controller.enqueue(new Uint8Array(8));
          controller.close();
        },
      },
      { highWaterMark: 0 },
    );
    const response = await route(
      apiRequest('/x', {
        method: 'POST',
        body: stream,
        headers: {
          'content-type': 'application/json',
          'content-length': String(MAX_BODY_BYTES + 1),
        },
      }),
    );
    await expectProblem(response, 413, 'PAYLOAD_TOO_LARGE');
    expect(pulled).toBe(0);
  });

  it('AC-23: a chunked body without Content-Length is cut off as soon as it crosses the limit', async () => {
    const { route } = setup();
    const chunkBytes = 1024;
    const totalChunks = 1000;
    let pulled = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        controller.enqueue(new Uint8Array(chunkBytes).fill(0x61));
        if (pulled === totalChunks) controller.close();
      },
    });
    const response = await route(
      apiRequest('/x', {
        method: 'POST',
        body: stream,
        headers: { 'content-type': 'application/json' },
      }),
    );
    await expectProblem(response, 413, 'PAYLOAD_TOO_LARGE');
    expect(pulled).toBeLessThan(MAX_BODY_BYTES / chunkBytes + 4);
  });

  it('accepts a body of exactly 16 KiB', async () => {
    const { route } = setup();
    const overhead = JSON.stringify({ name: '' }).length;
    const exact = `{"name":"${'a'.repeat(MAX_BODY_BYTES - overhead)}"}`;
    expect(new TextEncoder().encode(exact).byteLength).toBe(MAX_BODY_BYTES);
    const wide = createTestPipeline().withRoute(
      { ...PUBLIC_POLICY, body: z.object({ name: z.string() }).strict() },
      () => json(200, {}),
    );
    const response = await wide(
      apiRequest('/x', {
        method: 'POST',
        body: exact,
        headers: { 'content-type': 'application/json' },
      }),
    );
    expect(response.status).toBe(200);
    // and the strict 50-char schema of the shared setup still refuses the long name
    const refused = await route(
      apiRequest('/x', {
        method: 'POST',
        body: exact,
        headers: { 'content-type': 'application/json' },
      }),
    );
    expect(refused.status).toBe(400);
  });

  it('AC-23: an unknown field → 400 VALIDATION_ERROR pointing at the field', async () => {
    const { route, handler } = setup();
    const response = await route(
      apiRequest('/x', { method: 'POST', json: { name: 'a', role: 'ceo', isAdmin: true } }),
    );
    const body = await expectProblem(response, 400, 'VALIDATION_ERROR');
    expect(body['errors']).toEqual([
      { path: 'body.role', message: 'Unknown field' },
      { path: 'body.isAdmin', message: 'Unknown field' },
    ]);
    expect(handler).not.toHaveBeenCalled();
  });

  it.each([
    ['malformed JSON', '{"name":'],
    ['invalid UTF-8', 'ÿþ'],
  ])('%s → 400 VALIDATION_ERROR on "body"', async (_label, raw) => {
    const { route } = setup();
    const bytes = _label === 'invalid UTF-8' ? new Uint8Array([0x7b, 0xff, 0xfe, 0x7d]) : raw;
    const stream =
      typeof bytes === 'string'
        ? bytes
        : new ReadableStream<Uint8Array>({
            start(controller) {
              controller.enqueue(bytes);
              controller.close();
            },
          });
    const response = await route(
      apiRequest('/x', {
        method: 'POST',
        body: stream,
        headers: { 'content-type': 'application/json' },
      }),
    );
    const body = await expectProblem(response, 400, 'VALIDATION_ERROR');
    expect(body['errors']).toEqual([{ path: 'body', message: 'Malformed JSON' }]);
  });

  describe('a route without a body schema ignores the request body entirely', () => {
    // logout, enrollTotp and resetClientUserPassword document no 400, 413 or 415.
    const noBodyRoute = () => {
      const { withRoute } = createTestPipeline();
      const handler = vi.fn(({ body }: { body: unknown }) => json(200, { body: body ?? null }));
      return { route: withRoute(PUBLIC_POLICY, handler), handler };
    };

    it('serves a request that carries a JSON body, and the handler sees no body', async () => {
      const { route, handler } = noBodyRoute();
      const response = await route(apiRequest('/x', { method: 'POST', json: { anything: 1 } }));
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ body: null });
      expect(handler).toHaveBeenCalledTimes(1);
    });

    it.each([
      [
        'a body of another Content-Type (no 415)',
        { body: 'x=1', headers: { 'content-type': 'text/plain' } },
      ],
      [
        'malformed JSON (no 400)',
        { body: '{"a":', headers: { 'content-type': 'application/json' } },
      ],
      [
        'a body above 16 KiB (no 413)',
        { body: 'a'.repeat(MAX_BODY_BYTES * 2), headers: { 'content-type': 'application/json' } },
      ],
      [
        'a lying and a huge Content-Length (no 413)',
        { body: 'x', headers: { 'content-type': 'application/json', 'content-length': '999999' } },
      ],
      ['a body without a Content-Type (no 415)', { body: 'abc', headers: { 'content-type': '' } }],
    ])('serves a request with %s', async (_label, init) => {
      const { route, handler } = noBodyRoute();
      const response = await route(apiRequest('/x', { method: 'POST', ...init }));
      expect(response.status).toBe(200);
      expect(handler).toHaveBeenCalledTimes(1);
    });

    it('does not even read the body stream', async () => {
      const { route } = noBodyRoute();
      let pulled = 0;
      const stream = new ReadableStream<Uint8Array>(
        {
          pull(controller) {
            pulled += 1;
            controller.enqueue(new Uint8Array(1024));
            controller.close();
          },
        },
        { highWaterMark: 0 },
      );
      const response = await route(apiRequest('/x', { method: 'POST', body: stream }));
      expect(response.status).toBe(200);
      expect(pulled).toBe(0);
    });

    it('still enforces the Origin check on unsafe methods (403)', async () => {
      const { route, handler } = noBodyRoute();
      const response = await route(
        apiRequest('/x', { method: 'POST', json: { a: 1 }, origin: 'https://evil.test' }),
      );
      await expectProblem(response, 403, 'ORIGIN_NOT_ALLOWED');
      expect(handler).not.toHaveBeenCalled();
    });
  });

  it('the full body checks still apply to a route WITH a body schema', async () => {
    const { route } = setup();
    const unsupported = await route(
      apiRequest('/x', { method: 'POST', body: 'x', headers: { 'content-type': 'text/plain' } }),
    );
    expect(unsupported.status).toBe(415);
    const tooLarge = await route(
      apiRequest('/x', { method: 'POST', json: { name: 'a'.repeat(MAX_BODY_BYTES) } }),
    );
    expect(tooLarge.status).toBe(413);
  });

  it('a query string on a route without a query schema is ignored (getHealth documents no 400)', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, () => json(200, { ok: true }));
    const response = await route(apiRequest('/x?utm_source=mail&cache=1&a=1&a=2'));
    expect(response.status).toBe(200);
  });

  it('a route WITH a query schema stays strict about unknown parameters', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute({ ...PUBLIC_POLICY, query: z.object({ q: z.string() }).strict() }, () =>
      json(200, {}),
    );
    expect((await route(apiRequest('/x?q=a'))).status).toBe(200);
    expect((await route(apiRequest('/x?q=a&utm_source=mail'))).status).toBe(400);
  });

  it('an empty body on a route with a body schema → 400 pointing at "body"', async () => {
    const { route } = setup();
    const response = await route(apiRequest('/x', { method: 'POST' }));
    const body = await expectProblem(response, 400, 'VALIDATION_ERROR');
    expect(body['errors']).toEqual([{ path: 'body', message: expect.any(String) as string }]);
  });
});

describe('withRoute: fixed pipeline order (SEC-02)', () => {
  const orderedRoute = (options: Parameters<typeof createTestPipeline>[0] = {}) => {
    const pipeline = createTestPipeline(options);
    const handler = vi.fn(() => json(200, { ok: true }));
    const route = pipeline.withRoute(
      {
        ...CEO_POLICY,
        body: bodySchema,
        query: z.object({ q: z.string().max(5) }).strict(),
      },
      handler,
    );
    return { ...pipeline, route, handler };
  };

  it('no session and an invalid body → 401, not 400', async () => {
    const { route, handler } = orderedRoute({ principal: null });
    const response = await route(
      apiRequest('/x?q=far-too-long', { method: 'POST', json: { wrong: true } }),
    );
    await expectProblem(response, 401, 'UNAUTHENTICATED');
    expect(handler).not.toHaveBeenCalled();
  });

  it('wrong role and an invalid body → 403, not 400', async () => {
    const { route } = orderedRoute({
      principal: principalFixture({ role: 'client', clientId: 'c1' }),
    });
    const response = await route(
      apiRequest('/x?q=far-too-long', { method: 'POST', json: { wrong: true } }),
    );
    await expectProblem(response, 403, 'FORBIDDEN');
  });

  it('authorized but invalid input → 400 listing every problem of body and query', async () => {
    const { route } = orderedRoute({ principal: principalFixture() });
    const response = await route(
      apiRequest('/x?q=far-too-long', { method: 'POST', json: { name: '' } }),
    );
    const body = await expectProblem(response, 400, 'VALIDATION_ERROR');
    const paths = (body['errors'] as { path: string }[]).map((error) => error.path);
    expect(paths).toEqual(['query.q', 'body.name']);
  });

  it('a bad Origin is refused before the body is read and before authentication runs', async () => {
    const { route, principalResolver } = orderedRoute({ principal: principalFixture() });
    const response = await route(
      apiRequest('/x', { method: 'POST', json: { name: 'a' }, origin: 'https://evil.test' }),
    );
    await expectProblem(response, 403, 'ORIGIN_NOT_ALLOWED');
    expect(principalResolver.calls).toHaveLength(0);
  });

  it('a transport error (415) wins over authentication (401)', async () => {
    const { route } = orderedRoute({ principal: null });
    const response = await route(
      apiRequest('/x', { method: 'POST', body: 'x', headers: { 'content-type': 'text/plain' } }),
    );
    expect(response.status).toBe(415);
  });

  it('runs the handler with the parsed input once every step passes', async () => {
    const { route, handler } = orderedRoute({ principal: principalFixture() });
    const response = await route(apiRequest('/x?q=ab', { method: 'POST', json: { name: 'Acme' } }));
    expect(response.status).toBe(200);
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('authentication that returns a principal exactly once per request', async () => {
    const { route, principalResolver } = orderedRoute({ principal: principalFixture() });
    await route(apiRequest('/x?q=ab', { method: 'POST', json: { name: 'Acme' } }));
    expect(principalResolver.calls).toHaveLength(1);
  });
});

describe('withRoute: what Next passes as context', () => {
  it('treats params that resolve to undefined (static routes in Next 16) as no params', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, () => json(200, { ok: true }));
    const response = await route(apiRequest('/x'), {
      params: Promise.resolve(undefined),
    });
    expect(response.status).toBe(200);
  });

  it('works when called without a context at all', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, () => json(200, {}));
    expect((await route(apiRequest('/x'))).status).toBe(200);
  });
});

describe('withRoute: a failing logger never changes the answer', () => {
  const throwingLogger = () => {
    const boom = () => {
      throw new Error('log sink is down');
    };
    return { info: boom, warn: boom, error: boom, child: () => throwingLogger() } as never;
  };
  const withBrokenLogger = (principal: Principal | null = null) =>
    createWithRoute(() => ({
      rateLimiter: createInMemoryRateLimiter(),
      principalResolver: createFakePrincipalResolver(principal),
      allowedOrigins: [TEST_APP_ORIGIN],
      requireClientIp: false,
      logger: throwingLogger(),
    }));

  it('still returns the success response', async () => {
    const route = withBrokenLogger()(PUBLIC_POLICY, () => json(200, { ok: true }));
    const response = await route(apiRequest('/x'));
    expect(response.status).toBe(200);
    expect(response.headers.get('x-request-id')).toMatch(REQUEST_ID_PATTERN);
  });

  it('still answers a denial with its own status (403), not a crash and never a 200', async () => {
    const handler = vi.fn(() => json(200, {}));
    const route = withBrokenLogger(principalFixture({ role: 'client', clientId: 'c1' }))(
      CEO_POLICY,
      handler,
    );
    const response = await route(apiRequest('/x'));
    expectSecurityEnvelope(response);
    await expectProblem(response, 403, 'FORBIDDEN');
    expect(handler).not.toHaveBeenCalled();
  });

  it('answers an unhandled exception with a well-formed 500', async () => {
    const route = withBrokenLogger()(PUBLIC_POLICY, () => {
      throw new Error('boom');
    });
    const response = await route(apiRequest('/x'));
    expectSecurityEnvelope(response);
    await expectProblem(response, 500, 'INTERNAL_ERROR');
  });
});

describe('withRoute: request setup failures are fail-closed problem responses', () => {
  const route = () => {
    const { withRoute } = createTestPipeline();
    return withRoute(PUBLIC_POLICY, () => json(200, { ok: true }));
  };

  it('a cookie header that cannot be read → 500 with the SEC-14 headers, handler never runs', async () => {
    const handler = vi.fn(() => json(200, {}));
    const { withRoute } = createTestPipeline();
    const guarded = withRoute(PUBLIC_POLICY, handler);
    const request = apiRequest('/x');
    Object.defineProperty(request, 'cookies', {
      get() {
        throw new Error('cannot parse cookies');
      },
    });
    const response = await guarded(request);
    expectSecurityEnvelope(response);
    await expectProblem(response, 500, 'INTERNAL_ERROR');
    expect(handler).not.toHaveBeenCalled();
  });

  it('a logger that cannot create the request child → 500 with the SEC-14 headers', async () => {
    const handler = vi.fn(() => json(200, {}));
    const brokenLogger = {
      child: () => {
        throw new Error('no child for you');
      },
      error: () => undefined,
    } as never;
    const withRoute = createWithRoute(() => ({
      rateLimiter: createInMemoryRateLimiter(),
      principalResolver: createFakePrincipalResolver(null),
      allowedOrigins: [TEST_APP_ORIGIN],
      requireClientIp: false,
      logger: brokenLogger,
    }));
    const response = await withRoute(PUBLIC_POLICY, handler)(apiRequest('/x'));
    expectSecurityEnvelope(response);
    await expectProblem(response, 500, 'INTERNAL_ERROR');
    expect(handler).not.toHaveBeenCalled();
  });

  it('dependencies that cannot be built (invalid env) → 500 with the SEC-14 headers', async () => {
    const handler = vi.fn(() => json(200, {}));
    const withRoute = createWithRoute(() => {
      throw new Error('invalid environment');
    });
    const response = await withRoute(PUBLIC_POLICY, handler)(apiRequest('/x'));
    expectSecurityEnvelope(response);
    await expectProblem(response, 500, 'INTERNAL_ERROR');
    expect(handler).not.toHaveBeenCalled();
  });

  it('keeps working for later requests after a failed one', async () => {
    const guarded = route();
    expect((await guarded(apiRequest('/x'))).status).toBe(200);
  });

  it('uses one cached fallback logger for every setup failure', () => {
    expect(getFallbackLogger()).toBe(getFallbackLogger());
  });
});

describe('withRoute: cookies must go through the jar', () => {
  const cookieOnResponse = (response: Response) => response.headers.getSetCookie();

  it('a Set-Cookie written straight on the handler Response is a programming error: 500, no raw cookie', async () => {
    const { withRoute, logs } = createTestPipeline();
    const route = withRoute(
      PUBLIC_POLICY,
      () =>
        new Response('{}', {
          status: 200,
          headers: { 'Content-Type': 'application/json', 'Set-Cookie': 'sid=abc; Path=/' },
        }),
    );
    const response = await route(apiRequest('/x'));
    await expectProblem(response, 500, 'INTERNAL_ERROR');
    expect(cookieOnResponse(response)).toEqual([]);
    expect(response.headers.get('set-cookie')).toBeNull();
    const logged = logs.records().find((entry) => entry['level'] === 'error');
    expect(JSON.stringify(logged)).toContain('cookies jar');
  });

  it('also refuses cookies set through NextResponse.cookies', async () => {
    const { NextResponse } = await import('next/server');
    const { withRoute } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, () => {
      const response = NextResponse.json({ ok: true });
      response.cookies.set('sid', 'abc', { httpOnly: false, secure: false });
      return response;
    });
    const response = await route(apiRequest('/x'));
    expect(response.status).toBe(500);
    expect(cookieOnResponse(response)).toEqual([]);
  });

  it('cookies written through the jar still go out, with the forced flags, on a success response', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, ({ cookies }) => {
      cookies.set('sid', 'abc');
      return json(200, {});
    });
    const [cookie] = cookieOnResponse(await route(apiRequest('/x')));
    expect(cookie).toMatch(/HttpOnly/i);
    expect(cookie).toMatch(/Secure/i);
    expect(cookie).toMatch(/SameSite=lax/i);
  });

  it('a handler cookie on a thrown or returned DomainError is not a Response cookie problem', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, () => new NotFoundError('gone'));
    expect((await route(apiRequest('/x'))).status).toBe(404);
  });
});

describe('withRoute: failures in security steps deny the request', () => {
  it('a resolver that throws → denied (500), the handler never runs, nothing leaks', async () => {
    const handler = vi.fn(() => json(200, {}));
    const { withRoute, logs } = createTestPipeline({
      principal: () => {
        throw new Error('jwks fetch failed: SELECT leaked');
      },
    });
    const route = withRoute(CEO_POLICY, handler);
    const response = await route(apiRequest('/x'));
    await expectProblem(response, 500, 'INTERNAL_ERROR');
    expect(handler).not.toHaveBeenCalled();
    expect(logs.records().some((record) => record['level'] === 'error')).toBe(true);
  });

  it('a resolver that reports an outage with ServiceUnavailableError → 503 with Retry-After', async () => {
    const handler = vi.fn(() => json(200, {}));
    const { withRoute } = createTestPipeline({
      principal: () => {
        throw new ServiceUnavailableError('supabase timed out');
      },
    });
    const route = withRoute(CEO_POLICY, handler);
    const response = await route(apiRequest('/x'));
    await expectProblem(response, 503, 'SERVICE_UNAVAILABLE');
    expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expect(handler).not.toHaveBeenCalled();
  });

  it('a rate limiter that throws → 503 (E-22), the handler never runs, Retry-After is set', async () => {
    const handler = vi.fn(() => json(200, {}));
    const { withRoute } = createTestPipeline({
      rateLimiter: {
        consume: () => Promise.reject(new Error('relation "rate_limits" does not exist')),
      },
    });
    const route = withRoute(
      {
        ...PUBLIC_POLICY,
        rateLimit: [{ scope: 'ip', group: 'reads', limit: 5, windowSeconds: 60 }],
      },
      handler,
    );
    const response = await route(apiRequest('/x'));
    const body = await expectProblem(response, 503, 'SERVICE_UNAVAILABLE');
    expect(JSON.stringify(body)).not.toContain('rate_limits');
    expect(Number(response.headers.get('retry-after'))).toBeGreaterThanOrEqual(1);
    expect(handler).not.toHaveBeenCalled();
  });

  it('a rate limiter that answers garbage is treated as a failure (503), not as "allowed"', async () => {
    const handler = vi.fn(() => json(200, {}));
    const { withRoute } = createTestPipeline({
      rateLimiter: { consume: () => Promise.resolve({} as never) },
    });
    const route = withRoute(
      {
        ...PUBLIC_POLICY,
        rateLimit: [{ scope: 'ip', group: 'reads', limit: 5, windowSeconds: 60 }],
      },
      handler,
    );
    const response = await route(apiRequest('/x'));
    expect(response.status).toBe(503);
    expect(handler).not.toHaveBeenCalled();
  });

  it('a handler that returns something that is not a Response → 500', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(PUBLIC_POLICY, (() => ({ status: 'ok' })) as never);
    const response = await route(apiRequest('/x'));
    expect(response.status).toBe(500);
  });
});
