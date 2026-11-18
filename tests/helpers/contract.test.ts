import { describe, expect, it } from 'vitest';
import { expectToMatchContract } from './contract';

const REQUEST_ID = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';
const UUID = '6f1d5a3e-3b0c-4f43-9a55-0d3f6f6f1a11';

const problem = (overrides: Record<string, unknown> = {}) => ({
  type: 'about:blank',
  title: 'Too many requests',
  status: 429,
  code: 'RATE_LIMITED',
  requestId: REQUEST_ID,
  ...overrides,
});

/** Runs the helper and returns the failure message ('' when it passes). */
function failureOf(operationId: string, status: number, body: unknown): string {
  try {
    expectToMatchContract(operationId, status, body);
    return '';
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

describe('expectToMatchContract', () => {
  describe('application/json responses', () => {
    it('AC-26: accepts a valid body (getHealth 200)', () => {
      expect(() => expectToMatchContract('getHealth', 200, { status: 'ok' })).not.toThrow();
    });

    it('AC-26: rejects an extra property where the schema has additionalProperties: false', () => {
      const message = failureOf('getHealth', 200, { status: 'ok', version: '1.2.3' });
      expect(message).toMatch(/additional properties/i);
      expect(message).toContain('getHealth');
    });

    it('rejects a value outside the enum, a missing required field and a wrong type', () => {
      expect(failureOf('getHealth', 200, { status: 'down' })).not.toBe('');
      expect(failureOf('getHealth', 200, {})).toMatch(/required property 'status'/);
      expect(failureOf('getHealth', 200, { status: 1 })).not.toBe('');
      expect(failureOf('getHealth', 200, 'ok')).not.toBe('');
      expect(failureOf('getHealth', 200, undefined)).not.toBe('');
    });

    it('resolves nested $refs and formats (listClients 200)', () => {
      const list = (items: unknown[], nextCursor: unknown) => ({ items, nextCursor });
      expect(() => expectToMatchContract('listClients', 200, list([], null))).not.toThrow();
      expect(failureOf('listClients', 200, list([], 'has space'))).toMatch(/nextCursor/);
      expect(failureOf('listClients', 200, list([{ id: 'not-a-uuid' }], null))).not.toBe('');
      expect(failureOf('listClients', 200, { ...list([], null), extra: 1 })).toMatch(/additional/i);
    });

    it('checks the uuid format (getSession 200)', () => {
      const session = (id: string) => ({
        user: { id, displayName: 'Maria', role: 'ceo' },
        client: null,
        aal: 'aal1',
        pendingActions: [],
      });
      // the valid body passes: an empty failure message means it did not throw
      expect(failureOf('getSession', 200, session(UUID))).toBe('');
      const message = failureOf('getSession', 200, session('not-a-uuid'));
      expect(message).toMatch(/\/user\/id/);
      expect(message).toMatch(/format "uuid"/);
    });

    it('checks the date-time format (listClients 200)', () => {
      const client = (createdAt: string) => ({
        id: UUID,
        name: 'Acme',
        archived: false,
        archivedAt: null,
        activeProcessCount: 0,
        createdAt,
        updatedAt: '2026-11-15T12:00:00.000Z',
      });
      const list = (createdAt: string) => ({ items: [client(createdAt)], nextCursor: null });
      expect(failureOf('listClients', 200, list('2026-11-15T12:00:00.000Z'))).toBe('');
      expect(failureOf('listClients', 200, list('yesterday'))).toMatch(/format "date-time"/);
    });
  });

  describe('application/problem+json responses (through $ref to components.responses)', () => {
    it('AC-26: accepts a valid problem for each documented error response', () => {
      expect(() => expectToMatchContract('getHealth', 429, problem())).not.toThrow();
      expect(() =>
        expectToMatchContract('login', 401, problem({ status: 401, code: 'INVALID_CREDENTIALS' })),
      ).not.toThrow();
      expect(() =>
        expectToMatchContract('login', 403, problem({ status: 403, code: 'ORIGIN_NOT_ALLOWED' })),
      ).not.toThrow();
      expect(() =>
        expectToMatchContract('login', 413, problem({ status: 413, code: 'PAYLOAD_TOO_LARGE' })),
      ).not.toThrow();
      expect(() =>
        expectToMatchContract(
          'login',
          415,
          problem({ status: 415, code: 'UNSUPPORTED_MEDIA_TYPE' }),
        ),
      ).not.toThrow();
      expect(() =>
        expectToMatchContract('login', 500, problem({ status: 500, code: 'INTERNAL_ERROR' })),
      ).not.toThrow();
    });

    it('accepts the optional detail and rejects an oversized one', () => {
      expect(() =>
        expectToMatchContract('getHealth', 429, problem({ detail: 'Try later.' })),
      ).not.toThrow();
      expect(failureOf('getHealth', 429, problem({ detail: 'x'.repeat(501) }))).toMatch(/detail/);
    });

    it('rejects a code that is not in the ErrorCode enum', () => {
      expect(failureOf('getHealth', 429, problem({ code: 'TOO_MANY' }))).toMatch(/code/);
    });

    it('rejects a malformed requestId and a missing required member', () => {
      expect(failureOf('getHealth', 429, problem({ requestId: 'short' }))).toMatch(/requestId/);
      expect(failureOf('getHealth', 429, problem({ requestId: 'has space 123' }))).not.toBe('');
      const { code: _code, ...withoutCode } = problem();
      expect(failureOf('getHealth', 429, withoutCode)).toMatch(/required property 'code'/);
    });

    it('rejects a problem status outside 400..599', () => {
      expect(failureOf('getHealth', 429, problem({ status: 200 }))).not.toBe('');
    });

    it('requires errors[] on a 400 (ValidationProblem) and checks each entry', () => {
      const bad = problem({ status: 400, code: 'VALIDATION_ERROR' });
      expect(failureOf('login', 400, bad)).toMatch(/required property 'errors'/);

      const ok = { ...bad, errors: [{ path: 'body.email', message: 'Invalid input' }] };
      expect(() => expectToMatchContract('login', 400, ok)).not.toThrow();

      const extra = { ...bad, errors: [{ path: 'body.email', message: 'x', value: 'leak' }] };
      expect(failureOf('login', 400, extra)).toMatch(/additional/i);

      const tooMany = {
        ...bad,
        errors: Array.from({ length: 51 }, () => ({ path: 'body.a', message: 'x' })),
      };
      expect(failureOf('login', 400, tooMany)).toMatch(/more than 50|fewer than 51|NOT have more/i);
    });

    it('allows extensions on a problem (currentStageId on a 409)', () => {
      const stale = problem({
        status: 409,
        code: 'STALE_STAGE',
        currentStageId: UUID,
      });
      expect(() => expectToMatchContract('approveCurrentStage', 409, stale)).not.toThrow();
    });
  });

  describe('responses without a body', () => {
    it('accepts no body on a 204 and rejects one', () => {
      expect(() => expectToMatchContract('logout', 204, undefined)).not.toThrow();
      expect(() => expectToMatchContract('logout', 204, null)).not.toThrow();
      expect(() => expectToMatchContract('logout', 204, '')).not.toThrow();
      expect(failureOf('logout', 204, { status: 'ok' })).toMatch(/no response body/);
    });
  });

  describe('things the contract does not describe fail', () => {
    it('AC-26: an unknown operation', () => {
      const message = failureOf('doesNotExist', 200, {});
      expect(message).toMatch(/unknown operation "doesNotExist"/);
      expect(message).toContain('getHealth');
    });

    it('AC-26: a status the operation does not document', () => {
      const message = failureOf('getHealth', 404, problem({ status: 404, code: 'NOT_FOUND' }));
      expect(message).toMatch(/documents no such status/);
      expect(message).toContain('200');
      expect(message).toContain('429');
    });

    it('does not confuse the media types: a problem body is not a valid 200 Health', () => {
      expect(failureOf('getHealth', 200, problem())).not.toBe('');
    });
  });

  describe('failure messages are readable', () => {
    it('name the operation, method, path and status, the schema path and the offending body', () => {
      const message = failureOf('getHealth', 200, { status: 'down' });
      expect(message).toContain('GET /health (getHealth) → 200');
      expect(message).toContain('application/json');
      expect(message).toContain('body/status');
      expect(message).toContain('{"status":"down"}');
    });

    it('truncate a huge body in the message', () => {
      const message = failureOf('getHealth', 200, { status: 'x'.repeat(5000) });
      expect(message.length).toBeLessThan(2000);
    });
  });
});

describe('expectToMatchContract with the Response (status, Content-Type and declared headers)', () => {
  const requestId = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';

  const healthResponse = (headers: Record<string, string> = {}) =>
    new Response(JSON.stringify({ status: 'ok' }), {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
        'X-Request-Id': requestId,
        'Cache-Control': 'no-store',
        ...headers,
      },
    });

  const problemResponse = (status: number, headers: Record<string, string> = {}) =>
    new Response(JSON.stringify(problem({ status })), {
      status,
      headers: {
        'Content-Type': 'application/problem+json',
        'X-Request-Id': requestId,
        'Cache-Control': 'no-store',
        ...headers,
      },
    });

  /** Runs the helper with a Response and returns the failure message ('' when it passes). */
  function failureWith(
    operationId: string,
    status: number,
    body: unknown,
    response: Response,
  ): string {
    try {
      expectToMatchContract(operationId, status, body, response);
      return '';
    } catch (error) {
      return error instanceof Error ? error.message : String(error);
    }
  }

  it('AC-26: passes a Response that matches the contract, headers included', () => {
    expect(failureWith('getHealth', 200, { status: 'ok' }, healthResponse())).toBe('');
  });

  it('accepts a media type with parameters and a different case', () => {
    const response = healthResponse({ 'Content-Type': 'Application/JSON; charset=utf-8' });
    expect(failureWith('getHealth', 200, { status: 'ok' }, response)).toBe('');
  });

  it('fails when the Response has a different status than the one declared', () => {
    expect(failureWith('getHealth', 429, problem(), healthResponse())).toMatch(/status 200/);
  });

  it('fails when the Content-Type is not the documented media type', () => {
    const wrongType = healthResponse({ 'Content-Type': 'text/plain' });
    expect(failureWith('getHealth', 200, { status: 'ok' }, wrongType)).toMatch(
      /documents Content-Type application\/json/,
    );
    // a problem served as plain application/json is a contract violation too
    const asJson = problemResponse(429, {
      'Retry-After': '30',
      'Content-Type': 'application/json',
    });
    expect(failureWith('getHealth', 429, problem(), asJson)).toMatch(/application\/problem\+json/);
  });

  it('fails when the Content-Type header is missing', () => {
    const response = new Response(JSON.stringify({ status: 'ok' }), {
      status: 200,
      headers: { 'X-Request-Id': requestId, 'Cache-Control': 'no-store' },
    });
    response.headers.delete('content-type');
    expect(failureWith('getHealth', 200, { status: 'ok' }, response)).toMatch(/Content-Type/);
  });

  describe('X-Request-Id', () => {
    it('fails when it is missing', () => {
      const response = healthResponse();
      response.headers.delete('x-request-id');
      expect(failureWith('getHealth', 200, { status: 'ok' }, response)).toMatch(
        /declares the header X-Request-Id/,
      );
    });

    it.each(['short', 'has space in it', 'a'.repeat(65), 'under_score_id_1'])(
      'fails when it does not match ^[A-Za-z0-9-]{8,64}$: %j',
      (value) => {
        const response = healthResponse({ 'X-Request-Id': value });
        expect(failureWith('getHealth', 200, { status: 'ok' }, response)).toMatch(
          /header X-Request-Id does not match/,
        );
      },
    );
  });

  describe('Cache-Control (declared on every response since 1.0.0-draft.4)', () => {
    it('fails when it is missing', () => {
      const response = healthResponse();
      response.headers.delete('cache-control');
      expect(failureWith('getHealth', 200, { status: 'ok' }, response)).toMatch(
        /declares the header Cache-Control/,
      );
    });

    it('fails when it is anything but no-store', () => {
      const response = healthResponse({ 'Cache-Control': 'max-age=60' });
      expect(failureWith('getHealth', 200, { status: 'ok' }, response)).toMatch(
        /header Cache-Control does not match/,
      );
    });

    it('is declared on the error responses too', () => {
      const response = problemResponse(429, { 'Retry-After': '30' });
      response.headers.delete('cache-control');
      expect(failureWith('getHealth', 429, problem(), response)).toMatch(
        /declares the header Cache-Control/,
      );
    });
  });

  describe('Retry-After on 429 and 503', () => {
    it('AC-26: passes with an integer of at least 1', () => {
      expect(
        failureWith('getHealth', 429, problem(), problemResponse(429, { 'Retry-After': '1' })),
      ).toBe('');
      expect(
        failureWith('getHealth', 429, problem(), problemResponse(429, { 'Retry-After': '900' })),
      ).toBe('');
      const unavailable = problem({ status: 503, code: 'SERVICE_UNAVAILABLE' });
      expect(
        failureWith('login', 503, unavailable, problemResponse(503, { 'Retry-After': '5' })),
      ).toBe('');
    });

    it('fails when it is missing on a 429 and on a 503', () => {
      expect(failureWith('getHealth', 429, problem(), problemResponse(429))).toMatch(
        /declares the header Retry-After/,
      );
      const unavailable = problem({ status: 503, code: 'SERVICE_UNAVAILABLE' });
      expect(failureWith('login', 503, unavailable, problemResponse(503))).toMatch(
        /declares the header Retry-After/,
      );
    });

    it.each(['0', '-3', 'soon', '1.5', '', 'Wed, 21 Oct 2026 07:28:00 GMT'])(
      'fails for the value %j (must be an integer >= 1)',
      (value) => {
        const response = problemResponse(429, { 'Retry-After': value });
        expect(failureWith('getHealth', 429, problem(), response)).toMatch(/header Retry-After/);
      },
    );
  });

  describe('503 on authenticated operations (the contract documents it on all of them)', () => {
    const unavailable = problem({ status: 503, code: 'SERVICE_UNAVAILABLE' });

    it.each([
      'logout',
      'getSession',
      'changePassword',
      'enrollTotp',
      'verifyTotp',
      'listMyProcesses',
      'getMyProcess',
      'listClients',
      'createClient',
      'approveCurrentStage',
    ])('accepts a 503 problem with Retry-After for %s', (operationId) => {
      expect(
        failureWith(operationId, 503, unavailable, problemResponse(503, { 'Retry-After': '5' })),
      ).toBe('');
      expect(failureWith(operationId, 503, unavailable, problemResponse(503))).toMatch(
        /declares the header Retry-After/,
      );
    });

    it('still refuses a 503 where the contract documents none: getHealth is public, its limiter is in memory', () => {
      expect(failureOf('getHealth', 503, unavailable)).toMatch(/documents no such status/);
    });
  });

  describe('Set-Cookie and Location', () => {
    it('requires the Set-Cookie of the logout response (204 clears the cookie)', () => {
      const withCookie = new Response(null, {
        status: 204,
        headers: {
          'X-Request-Id': requestId,
          'Cache-Control': 'no-store',
          'Set-Cookie': '__Host-rt-session=; Max-Age=0; Path=/',
        },
      });
      expect(failureWith('logout', 204, undefined, withCookie)).toBe('');
      const without = new Response(null, {
        status: 204,
        headers: { 'X-Request-Id': requestId, 'Cache-Control': 'no-store' },
      });
      expect(failureWith('logout', 204, undefined, without)).toMatch(
        /declares the header Set-Cookie/,
      );
    });

    it('the Set-Cookie of the changePassword 204 is optional: it passes with and without it', () => {
      const answer = (headers: Record<string, string>) =>
        new Response(null, {
          status: 204,
          headers: { 'X-Request-Id': requestId, 'Cache-Control': 'no-store', ...headers },
        });
      expect(failureWith('changePassword', 204, undefined, answer({}))).toBe('');
      expect(
        failureWith(
          'changePassword',
          204,
          undefined,
          answer({ 'Set-Cookie': '__Host-rt-session=x; HttpOnly; Secure; SameSite=Lax; Path=/' }),
        ),
      ).toBe('');
    });

    it('requires the Location header of a 201', () => {
      const created = (headers: Record<string, string>) =>
        new Response(
          JSON.stringify({
            id: UUID,
            name: 'Acme',
            archived: false,
            archivedAt: null,
            activeProcessCount: 0,
            processCount: 0,
            createdAt: '2026-11-15T12:00:00.000Z',
            updatedAt: '2026-11-15T12:00:00.000Z',
          }),
          {
            status: 201,
            headers: {
              'Content-Type': 'application/json',
              'X-Request-Id': requestId,
              'Cache-Control': 'no-store',
              ...headers,
            },
          },
        );
      const body = {
        id: UUID,
        name: 'Acme',
        archived: false,
        archivedAt: null,
        activeProcessCount: 0,
        processCount: 0,
        createdAt: '2026-11-15T12:00:00.000Z',
        updatedAt: '2026-11-15T12:00:00.000Z',
      };
      expect(
        failureWith(
          'createClient',
          201,
          body,
          created({ Location: `/api/v1/admin/clients/${UUID}` }),
        ),
      ).toBe('');
      expect(failureWith('createClient', 201, body, created({}))).toMatch(
        /declares the header Location/,
      );
    });
  });

  it('still checks the body when a Response is passed', () => {
    expect(failureWith('getHealth', 200, { status: 'down' }, healthResponse())).toMatch(
      /does not match the application\/json schema/,
    );
  });

  it('does not consume the body of the Response it is given', async () => {
    const response = healthResponse();
    expectToMatchContract('getHealth', 200, { status: 'ok' }, response);
    expect(await response.json()).toEqual({ status: 'ok' });
  });
});
