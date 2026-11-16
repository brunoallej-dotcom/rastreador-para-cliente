import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import {
  ConflictError,
  NotFoundError,
  PENDING_ACTION_PRIORITY,
  PENDING_ACTIONS,
  type PendingAction,
} from '@/shared/kernel';
import { json } from './responses';
import {
  apiRequest,
  CEO_POLICY,
  createTestPipeline,
  principalFixture,
  PUBLIC_POLICY,
} from './testing';

const PENDING_CODES: Record<PendingAction, string> = {
  CHANGE_PASSWORD: 'PASSWORD_CHANGE_REQUIRED',
  ENROLL_MFA: 'MFA_ENROLLMENT_REQUIRED',
  VERIFY_MFA: 'MFA_VERIFICATION_REQUIRED',
};

function subsets<T>(items: readonly T[]): T[][] {
  return items.reduce<T[][]>((all, item) => all.concat(all.map((set) => [...set, item])), [[]]);
}

async function call(
  pending: readonly PendingAction[],
  allowPending: readonly PendingAction[],
  role: 'ceo' | 'client' = 'ceo',
) {
  const { withRoute } = createTestPipeline({
    principal: principalFixture({ role, pendingActions: pending }),
  });
  const handler = vi.fn(() => json(200, {}));
  const route = withRoute({ ...CEO_POLICY, roles: ['ceo', 'client'], allowPending }, handler);
  const response = await route(apiRequest('/x'));
  return { response, handler };
}

describe('withRoute: pending actions (spec §3.5)', () => {
  it.each<{ pending: PendingAction[]; allow: PendingAction[]; code: string | null }>([
    { pending: [], allow: [], code: null },
    { pending: ['CHANGE_PASSWORD'], allow: [], code: 'PASSWORD_CHANGE_REQUIRED' },
    { pending: ['ENROLL_MFA'], allow: [], code: 'MFA_ENROLLMENT_REQUIRED' },
    { pending: ['VERIFY_MFA'], allow: [], code: 'MFA_VERIFICATION_REQUIRED' },
    { pending: ['CHANGE_PASSWORD'], allow: ['CHANGE_PASSWORD'], code: null },
    // CHANGE_PASSWORD > ENROLL_MFA
    { pending: ['CHANGE_PASSWORD', 'ENROLL_MFA'], allow: [], code: 'PASSWORD_CHANGE_REQUIRED' },
    { pending: ['ENROLL_MFA', 'CHANGE_PASSWORD'], allow: [], code: 'PASSWORD_CHANGE_REQUIRED' },
    {
      pending: ['CHANGE_PASSWORD', 'ENROLL_MFA'],
      allow: ['CHANGE_PASSWORD'],
      code: 'MFA_ENROLLMENT_REQUIRED',
    },
    {
      pending: ['CHANGE_PASSWORD', 'ENROLL_MFA'],
      allow: ['ENROLL_MFA'],
      code: 'PASSWORD_CHANGE_REQUIRED',
    },
    {
      pending: ['CHANGE_PASSWORD', 'ENROLL_MFA'],
      allow: ['CHANGE_PASSWORD', 'ENROLL_MFA'],
      code: null,
    },
    // ENROLL_MFA > VERIFY_MFA
    { pending: ['ENROLL_MFA', 'VERIFY_MFA'], allow: [], code: 'MFA_ENROLLMENT_REQUIRED' },
    {
      pending: ['VERIFY_MFA', 'ENROLL_MFA'],
      allow: ['ENROLL_MFA'],
      code: 'MFA_VERIFICATION_REQUIRED',
    },
    // CHANGE_PASSWORD > VERIFY_MFA
    { pending: ['CHANGE_PASSWORD', 'VERIFY_MFA'], allow: [], code: 'PASSWORD_CHANGE_REQUIRED' },
    {
      pending: ['CHANGE_PASSWORD', 'VERIFY_MFA'],
      allow: ['CHANGE_PASSWORD'],
      code: 'MFA_VERIFICATION_REQUIRED',
    },
    // all three
    { pending: [...PENDING_ACTIONS], allow: [], code: 'PASSWORD_CHANGE_REQUIRED' },
    { pending: [...PENDING_ACTIONS], allow: ['CHANGE_PASSWORD'], code: 'MFA_ENROLLMENT_REQUIRED' },
    {
      pending: [...PENDING_ACTIONS],
      allow: ['CHANGE_PASSWORD', 'ENROLL_MFA'],
      code: 'MFA_VERIFICATION_REQUIRED',
    },
    { pending: [...PENDING_ACTIONS], allow: [...PENDING_ACTIONS], code: null },
  ])('pending $pending with allowPending $allow → $code', async ({ pending, allow, code }) => {
    const { response, handler } = await call(pending, allow);
    if (code === null) {
      expect(response.status).toBe(200);
      expect(handler).toHaveBeenCalledTimes(1);
      return;
    }
    expect(response.status).toBe(403);
    expect((await response.json()) as { code: string }).toMatchObject({ code });
    expect(handler).not.toHaveBeenCalled();
  });

  it('follows the priority CHANGE_PASSWORD > ENROLL_MFA > VERIFY_MFA for every combination', async () => {
    expect([...PENDING_ACTION_PRIORITY]).toEqual(['CHANGE_PASSWORD', 'ENROLL_MFA', 'VERIFY_MFA']);
    for (const pending of subsets(PENDING_ACTIONS)) {
      for (const allow of subsets(PENDING_ACTIONS)) {
        const blocking = (['CHANGE_PASSWORD', 'ENROLL_MFA', 'VERIFY_MFA'] as const).find(
          (action) => pending.includes(action) && !allow.includes(action),
        );
        const { response } = await call(pending, allow);
        if (blocking === undefined) {
          expect(response.status, `${pending.join()} / ${allow.join()}`).toBe(200);
        } else {
          expect(response.status, `${pending.join()} / ${allow.join()}`).toBe(403);
          expect(
            ((await response.json()) as { code: string }).code,
            `${pending.join()} / ${allow.join()}`,
          ).toBe(PENDING_CODES[blocking]);
        }
      }
    }
  });

  it('first access of a CEO walks through the routes of the spec table in order', async () => {
    const routes = {
      password: ['CHANGE_PASSWORD', 'ENROLL_MFA'],
      enroll: ['ENROLL_MFA'],
      verify: ['ENROLL_MFA', 'VERIFY_MFA'],
      admin: [],
    } as const satisfies Record<string, readonly PendingAction[]>;

    const status = async (pending: PendingAction[], route: keyof typeof routes) =>
      (await call(pending, routes[route])).response.status;

    // login: aal1 with CHANGE_PASSWORD and ENROLL_MFA
    const first: PendingAction[] = ['CHANGE_PASSWORD', 'ENROLL_MFA'];
    expect(await status(first, 'password')).toBe(200);
    expect(await status(first, 'enroll')).toBe(403);
    expect(await status(first, 'admin')).toBe(403);
    // after the password change
    const second: PendingAction[] = ['ENROLL_MFA'];
    expect(await status(second, 'enroll')).toBe(200);
    expect(await status(second, 'verify')).toBe(200);
    expect(await status(second, 'admin')).toBe(403);
    // enrolled, still aal1
    const third: PendingAction[] = ['VERIFY_MFA'];
    expect(await status(third, 'verify')).toBe(200);
    expect(await status(third, 'admin')).toBe(403);
    // aal2, nothing pending
    expect(await status([], 'admin')).toBe(200);
  });

  it('checks the role before the pending actions (E-07: a client in /admin gets FORBIDDEN)', async () => {
    const { withRoute } = createTestPipeline({
      principal: principalFixture({
        role: 'client',
        clientId: 'c1',
        pendingActions: ['CHANGE_PASSWORD'],
      }),
    });
    const route = withRoute(CEO_POLICY, () => json(200, {}));
    const response = await route(apiRequest('/x'));
    expect(response.status).toBe(403);
    expect((await response.json()) as { code: string }).toMatchObject({ code: 'FORBIDDEN' });
  });

  it('a CEO in a client-only route gets FORBIDDEN', async () => {
    const { withRoute } = createTestPipeline({ principal: principalFixture({ role: 'ceo' }) });
    const route = withRoute({ ...CEO_POLICY, roles: ['client'] }, () => json(200, {}));
    expect((await route(apiRequest('/x'))).status).toBe(403);
  });

  it('denies a pending action it does not know (fail closed)', async () => {
    const { withRoute } = createTestPipeline({
      principal: principalFixture({ pendingActions: ['SOMETHING_NEW' as PendingAction] }),
    });
    const route = withRoute(CEO_POLICY, () => json(200, {}));
    expect((await route(apiRequest('/x'))).status).toBe(403);
  });
});

describe('withRoute: handler context', () => {
  const PROCESS_ID = '6f1d5a3e-3b0c-4f43-9a55-0d3f6f6f1a11';

  it('passes request, requestId, principal, parsed params/query/body, cookies and logger', async () => {
    const principal = principalFixture();
    const { withRoute } = createTestPipeline({ principal });
    const seen = vi.fn();
    const route = withRoute(
      {
        ...CEO_POLICY,
        params: z.object({ processId: z.uuid() }).strict(),
        query: z.object({ limit: z.coerce.number().int().default(10) }).strict(),
        body: z.object({ expectedStageId: z.uuid() }).strict(),
      },
      (context) => {
        seen(context);
        return json(200, {});
      },
    );
    const stageId = '0e0f2c5f-6a4d-4f8e-8a53-c1b7f0b8a001';
    const response = await route(
      apiRequest(`/p/${PROCESS_ID}?limit=5`, {
        method: 'POST',
        json: { expectedStageId: stageId },
        headers: { cookie: 'a=1' },
      }),
      { params: Promise.resolve({ processId: PROCESS_ID }) },
    );

    expect(response.status).toBe(200);
    const context = seen.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(context['principal']).toEqual(principal);
    expect(context['params']).toEqual({ processId: PROCESS_ID });
    expect(context['query']).toEqual({ limit: 5 });
    expect(context['body']).toEqual({ expectedStageId: stageId });
    expect(context['requestId']).toBe(response.headers.get('x-request-id'));
    expect((context['cookies'] as { get(name: string): string }).get('a')).toBe('1');
    expect(typeof (context['logger'] as { info: unknown }).info).toBe('function');
  });

  it('gives public routes a null principal and does not call the resolver', async () => {
    const { withRoute, principalResolver } = createTestPipeline({ principal: principalFixture() });
    const route = withRoute(PUBLIC_POLICY, ({ principal }) => json(200, { principal }));
    const response = await route(apiRequest('/x'));
    expect(await response.json()).toEqual({ principal: null });
    expect(principalResolver.calls).toHaveLength(0);
  });

  it('a malformed path param → 400 VALIDATION_ERROR at params.<name> (E-06)', async () => {
    const { withRoute } = createTestPipeline({ principal: principalFixture() });
    const handler = vi.fn(() => json(200, {}));
    const route = withRoute(
      {
        ...CEO_POLICY,
        params: z.object({ processId: z.uuid() }).strict(),
      },
      handler,
    );
    const response = await route(apiRequest('/p/not-a-uuid'), {
      params: Promise.resolve({ processId: 'not-a-uuid' }),
    });
    expect(response.status).toBe(400);
    const body = (await response.json()) as { errors: { path: string }[] };
    expect(body.errors.map((error) => error.path)).toEqual(['params.processId']);
    expect(handler).not.toHaveBeenCalled();
  });

  it('a dynamic route whose policy declares no params schema is a server error (fail closed)', async () => {
    const { withRoute } = createTestPipeline();
    const handler = vi.fn(() => json(200, {}));
    const route = withRoute(PUBLIC_POLICY, handler);
    const response = await route(apiRequest('/p/1'), { params: Promise.resolve({ id: '1' }) });
    expect(response.status).toBe(500);
    expect(handler).not.toHaveBeenCalled();
  });

  it('rejects an unknown query parameter when the route declares a query schema', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute({ ...PUBLIC_POLICY, query: z.object({ q: z.string() }).strict() }, () =>
      json(200, {}),
    );
    expect((await route(apiRequest('/x?q=a&extra=1'))).status).toBe(400);
  });

  it('rejects a repeated query parameter instead of silently picking one', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute({ ...PUBLIC_POLICY, query: z.object({ q: z.string() }).strict() }, () =>
      json(200, {}),
    );
    expect((await route(apiRequest('/x?q=a&q=b'))).status).toBe(400);
  });

  it('turns a DomainError returned or thrown by the handler into the same problem', async () => {
    const { withRoute } = createTestPipeline();
    const returned = withRoute(PUBLIC_POLICY, () => new NotFoundError('x'));
    const thrown = withRoute(PUBLIC_POLICY, () => {
      throw new NotFoundError('x');
    });
    const [a, b] = await Promise.all([returned(apiRequest('/x')), thrown(apiRequest('/x'))]);
    expect(a.status).toBe(404);
    expect(b.status).toBe(404);
    const strip = (body: Record<string, unknown>) => ({ ...body, requestId: undefined });
    expect(strip((await a.json()) as Record<string, unknown>)).toEqual(
      strip((await b.json()) as Record<string, unknown>),
    );
  });

  it('adds problem extensions (STALE_STAGE currentStageId) but never lets them override standard members', async () => {
    const { withRoute } = createTestPipeline();
    const route = withRoute(
      PUBLIC_POLICY,
      () =>
        new ConflictError('stale', {
          detail: 'The stage changed.',
          extensions: { currentStageId: 'stage-2', status: 200, code: 'FORBIDDEN', requestId: 'x' },
        }),
    );
    const response = await route(apiRequest('/x'));
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toMatchObject({
      status: 409,
      code: 'CONFLICT',
      detail: 'The stage changed.',
      currentStageId: 'stage-2',
      requestId: response.headers.get('x-request-id'),
    });
  });
});
