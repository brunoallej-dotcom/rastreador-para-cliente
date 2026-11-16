/* eslint-disable @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-return --
   the @ts-expect-error cases below deliberately produce error-typed values */
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { json } from './responses';
import {
  CEO_POLICY,
  createTestPipeline,
  PUBLIC_POLICY,
  TEST_IP_RULE,
  TEST_USER_RULE,
} from './testing';

const { withRoute } = createTestPipeline();
const ok = () => json(200, {});

// Short constants, kept out of the calls below so Prettier never splits a line under
// the directive comments. Every policy below carries a rate limit, so each case fails for ITS reason only.
const IP = [TEST_IP_RULE];
const USER = [TEST_USER_RULE];
const BAD_SCOPE_RULE = { scope: 'org', group: 'reads', limit: 1, windowSeconds: 1 } as const;
const BAD_GROUP_RULE = { scope: 'ip', group: 'misc', limit: 1, windowSeconds: 1 } as const;
const NO_GROUP_RULE = { scope: 'ip', limit: 1, windowSeconds: 1 } as const;
const ACCOUNT_RULE = { scope: 'account', group: 'login', limit: 10, windowSeconds: 900 } as const;
const GLOBAL_RULE = { scope: 'global', group: 'login', limit: 300, windowSeconds: 300 } as const;

describe('withRoute: the policy is mandatory and typed', () => {
  it('does not compile without a policy or with an incomplete one', () => {
    // The assertions are the @ts-expect-error comments: `pnpm typecheck` fails if a call below
    // compiles. The function is never run.
    void (() => {
      // @ts-expect-error a policy is mandatory
      withRoute(ok);
      // @ts-expect-error there is no default policy: access must be written
      withRoute({ rateLimit: IP }, ok);
      // @ts-expect-error access must be 'public' or 'authenticated'
      withRoute({ access: 'anyone', rateLimit: IP }, ok);
      // @ts-expect-error authenticated routes need roles and allowPending
      withRoute({ access: 'authenticated', rateLimit: USER }, ok);
      // @ts-expect-error allowPending is required (use [] for none)
      withRoute({ access: 'authenticated', roles: ['ceo'], rateLimit: USER }, ok);
      // @ts-expect-error roles must not be empty
      withRoute({ ...CEO_POLICY, roles: [] }, ok);
      // @ts-expect-error unknown role
      withRoute({ ...CEO_POLICY, roles: ['admin'] }, ok);
      // @ts-expect-error unknown pending action
      withRoute({ ...CEO_POLICY, allowPending: ['NOPE'] }, ok);
      // @ts-expect-error a public route has no roles
      withRoute({ ...PUBLIC_POLICY, roles: ['ceo'] }, ok);
      // @ts-expect-error a policy for an authenticated route cannot carry accountKey
      withRoute({ ...CEO_POLICY, accountKey: () => 'k' }, ok);
    });
    expect(true).toBe(true);
  });

  it('does not compile without a rateLimit, with an empty one or with a malformed rule', () => {
    void (() => {
      // @ts-expect-error a public route must declare its rate limit
      withRoute({ access: 'public' }, ok);
      // @ts-expect-error an authenticated route must declare its rate limit
      withRoute({ access: 'authenticated', roles: ['ceo'], allowPending: [] }, ok);
      // @ts-expect-error the rate limit must not be empty
      withRoute({ ...PUBLIC_POLICY, rateLimit: [] }, ok);
      // @ts-expect-error rate-limit scope must be ip, account or user
      withRoute({ ...PUBLIC_POLICY, rateLimit: [BAD_SCOPE_RULE] }, ok);
      // @ts-expect-error rate-limit group must be one of the named groups
      withRoute({ ...PUBLIC_POLICY, rateLimit: [BAD_GROUP_RULE] }, ok);
      // @ts-expect-error every rate-limit rule needs its group
      withRoute({ ...PUBLIC_POLICY, rateLimit: [NO_GROUP_RULE] }, ok);
      // @ts-expect-error the global scope is a programmatic budget, never a route policy (F-02)
      withRoute({ ...PUBLIC_POLICY, rateLimit: [TEST_IP_RULE, GLOBAL_RULE] }, ok);
    });
    expect(true).toBe(true);
  });

  it('types principal as non-null on authenticated routes and null on public routes', () => {
    withRoute(CEO_POLICY, ({ principal }) => {
      const userId: string = principal.userId;
      const role: 'client' | 'ceo' = principal.role;
      return json(200, { userId, role });
    });
    withRoute(PUBLIC_POLICY, ({ principal }) => {
      const nothing: null = principal;
      return json(200, { nothing });
    });
    expect(true).toBe(true);
  });

  it('types params, query and body from the schemas of the policy', () => {
    withRoute(
      {
        ...CEO_POLICY,
        params: z.object({ processId: z.uuid() }).strict(),
        query: z.object({ limit: z.coerce.number().default(50) }).strict(),
        body: z.object({ expectedStageId: z.uuid() }).strict(),
      },
      ({ params, query, body }) => {
        const processId: string = params.processId;
        const limit: number = query.limit;
        const stageId: string = body.expectedStageId;
        // @ts-expect-error fields that are not in the schema do not exist
        const nope = body.other;
        return json(200, { processId, limit, stageId, nope });
      },
    );
    withRoute(PUBLIC_POLICY, ({ params, query, body }) => {
      // routes without schemas get undefined, not an unchecked object
      const none: undefined = params;
      const nothing: undefined = query;
      const empty: undefined = body;
      return json(200, { none, nothing, empty });
    });
    expect(true).toBe(true);
  });

  it('types accountKey with the validated body', () => {
    withRoute(
      {
        ...PUBLIC_POLICY,
        body: z.object({ email: z.string() }).strict(),
        rateLimit: [TEST_IP_RULE, ACCOUNT_RULE],
        accountKey: (body) => body.email.toLowerCase(),
      },
      ok,
    );
    void (() => {
      withRoute(
        {
          ...PUBLIC_POLICY,
          body: z.object({ email: z.string() }).strict(),
          // @ts-expect-error accountKey sees only fields of the body schema
          accountKey: (body) => body.password,
        },
        ok,
      );
    });
    expect(true).toBe(true);
  });
});

describe('withRoute: invalid policies fail when the route is defined, not on the first request', () => {
  const define = (policy: unknown) => () => withRoute(policy as never, ok);
  const ceo = { access: 'authenticated', roles: ['ceo'], allowPending: [], rateLimit: USER };
  const pub = { access: 'public', rateLimit: IP };

  it.each([
    ['empty roles', { ...ceo, roles: [] }],
    ['unknown role', { ...ceo, roles: ['admin'] }],
    ['missing allowPending', { access: 'authenticated', roles: ['ceo'], rateLimit: USER }],
    ['unknown pending action', { ...ceo, allowPending: ['X'] }],
    ['unknown access', { access: 'anyone', rateLimit: IP }],
    ['roles on a public route', { ...pub, roles: ['ceo'] }],
    ['no access at all', { rateLimit: IP }],
  ])('rejects %s', (_name, policy) => {
    expect(define(policy)).toThrow(/withRoute/);
  });

  describe('every route is rate limited', () => {
    it.each([
      ['a public route with no rateLimit', { access: 'public' }],
      [
        'an authenticated route with no rateLimit',
        { access: 'authenticated', roles: ['ceo'], allowPending: [] },
      ],
      ['a public route with an empty rateLimit', { access: 'public', rateLimit: [] }],
      ['an authenticated route with an empty rateLimit', { ...ceo, rateLimit: [] }],
    ])('rejects %s', (_name, policy) => {
      expect(define(policy)).toThrow(/rateLimit/);
    });

    it('rejects a public route whose rules have no ip rule', () => {
      const body = z.object({ email: z.string() }).strict();
      expect(
        define({ access: 'public', body, accountKey: () => 'k', rateLimit: [ACCOUNT_RULE] }),
      ).toThrow(/ip/);
    });

    it('accepts a public route with an ip rule and an authenticated one with a user rule', () => {
      expect(define(pub)).not.toThrow();
      expect(define(ceo)).not.toThrow();
    });
  });

  it.each([
    ['a zero limit', { scope: 'ip', group: 'reads', limit: 0, windowSeconds: 60 }],
    ['a fractional limit', { scope: 'ip', group: 'reads', limit: 1.5, windowSeconds: 60 }],
    ['a NaN window', { scope: 'ip', group: 'reads', limit: 5, windowSeconds: Number.NaN }],
    ['a negative window', { scope: 'ip', group: 'reads', limit: 5, windowSeconds: -1 }],
    ['an unknown scope', { scope: 'org', group: 'reads', limit: 5, windowSeconds: 60 }],
    ['an unknown group', { scope: 'ip', group: 'misc', limit: 5, windowSeconds: 60 }],
    ['no group', { scope: 'ip', limit: 5, windowSeconds: 60 }],
  ])('rejects a rate-limit rule with %s', (_name, rule) => {
    expect(define({ ...pub, rateLimit: [rule] })).toThrow(/withRoute/);
  });

  it('accepts every named group', () => {
    for (const group of [
      'login',
      'totp-enroll',
      'totp-verify',
      'password-change',
      'client-user-admin',
      'writes',
      'reads',
      'health',
      'session-upstream',
    ]) {
      expect(
        define({ ...pub, rateLimit: [{ scope: 'ip', group, limit: 5, windowSeconds: 60 }] }),
      ).not.toThrow();
    }
  });

  it('F-02: rejects the global scope in a route policy, with a message that points to the right API', () => {
    // past the types, as a JavaScript caller or a cast could
    expect(define({ ...pub, rateLimit: [TEST_IP_RULE, GLOBAL_RULE] })).toThrow(/global/);
    expect(define({ ...pub, rateLimit: [TEST_IP_RULE, GLOBAL_RULE] })).toThrow(
      /consumeGlobalBudget/,
    );
    expect(define({ ...ceo, rateLimit: [TEST_USER_RULE, GLOBAL_RULE] })).toThrow(/global/);
  });

  it('rejects a user rule on a public route and an account rule on an authenticated one', () => {
    const userRule = { scope: 'user', group: 'writes', limit: 5, windowSeconds: 60 };
    expect(define({ ...pub, rateLimit: [TEST_IP_RULE, userRule] })).toThrow(/user/);
    expect(define({ ...ceo, rateLimit: [TEST_USER_RULE, ACCOUNT_RULE] })).toThrow(/account/);
  });

  it('rejects an account rule without accountKey or without a body schema', () => {
    const rateLimit = [TEST_IP_RULE, ACCOUNT_RULE];
    const body = z.object({ email: z.string() }).strict();
    expect(define({ access: 'public', rateLimit, body })).toThrow(/accountKey/);
    expect(define({ access: 'public', rateLimit, accountKey: () => 'k' })).toThrow(/body/);
    expect(define({ access: 'public', rateLimit, body, accountKey: () => 'k' })).not.toThrow();
  });

  it.each(['params', 'query', 'body'])('rejects a non-strict %s schema', (part) => {
    expect(define({ ...pub, [part]: z.object({ a: z.string() }) })).toThrow(/strict/);
    expect(define({ ...pub, [part]: z.looseObject({ a: z.string() }) })).toThrow(/strict/);
  });

  it.each(['params', 'query', 'body'])('rejects a %s schema that is not an object', (part) => {
    expect(define({ ...pub, [part]: z.string() })).toThrow(/strict/);
  });

  it.each(['params', 'query', 'body'])('accepts a strict %s schema', (part) => {
    expect(define({ ...pub, [part]: z.object({ a: z.string() }).strict() })).not.toThrow();
    expect(define({ ...pub, [part]: z.strictObject({ a: z.string() }) })).not.toThrow();
  });
});
