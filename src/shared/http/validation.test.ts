import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { ValidationError } from '@/shared/kernel';
import { MAX_PROBLEM_ERRORS, problemBody } from './problem';
import { formatIssuePath, queryToObject, validateInput } from './validation';

function issuesOf(run: () => unknown) {
  try {
    run();
  } catch (error) {
    if (error instanceof ValidationError) return error.issues;
    throw error;
  }
  throw new Error('expected a ValidationError');
}

describe('formatIssuePath', () => {
  it.each([
    ['body', [], 'body'],
    ['body', ['name'], 'body.name'],
    ['body', ['stages', 2, 'name'], 'body.stages[2].name'],
    ['query', ['limit'], 'query.limit'],
    ['params', ['processId'], 'params.processId'],
    ['body', ['a', 0, 1, 'b'], 'body.a[0][1].b'],
  ] as const)('%s %j → %s', (part, path, expected) => {
    expect(formatIssuePath(part, path)).toBe(expected);
  });
});

describe('validateInput', () => {
  const body = z
    .object({
      name: z.string().trim().min(1).max(120),
      stages: z
        .array(z.object({ name: z.string().min(1) }).strict())
        .min(1)
        .max(30),
    })
    .strict();

  it('returns the parsed values; parts without a schema come back undefined', () => {
    const parsed = validateInput(
      { body },
      { params: {}, query: {}, body: { name: '  Acme ', stages: [{ name: 'Kickoff' }] } },
    );
    expect(parsed).toEqual({
      params: undefined,
      query: undefined,
      body: { name: 'Acme', stages: [{ name: 'Kickoff' }] },
    });
  });

  it('reports nested paths such as body.stages[2].name', () => {
    const issues = issuesOf(() =>
      validateInput(
        { body },
        {
          params: {},
          query: {},
          body: { name: 'x', stages: [{ name: 'a' }, { name: 'b' }, { name: '' }] },
        },
      ),
    );
    expect(issues.map((issue) => issue.path)).toEqual(['body.stages[2].name']);
  });

  it('reports one issue per unknown key, at the key', () => {
    const issues = issuesOf(() =>
      validateInput(
        { body },
        { params: {}, query: {}, body: { name: 'x', stages: [{ name: 'a' }], a: 1, b: 2 } },
      ),
    );
    expect(issues).toEqual([
      { path: 'body.a', message: 'Unknown field' },
      { path: 'body.b', message: 'Unknown field' },
    ]);
  });

  it('reports an unknown key inside a nested strict object', () => {
    const issues = issuesOf(() =>
      validateInput(
        { body },
        { params: {}, query: {}, body: { name: 'x', stages: [{ name: 'a', extra: 1 }] } },
      ),
    );
    expect(issues).toEqual([{ path: 'body.stages[0].extra', message: 'Unknown field' }]);
  });

  it('collects the problems of params, query and body together, in that order', () => {
    const issues = issuesOf(() =>
      validateInput(
        {
          params: z.object({ id: z.uuid() }).strict(),
          query: z.object({ q: z.string().max(2) }).strict(),
          body,
        },
        { params: { id: 'nope' }, query: { q: 'long' }, body: {} },
      ),
    );
    expect(issues.map((issue) => issue.path)).toEqual([
      'params.id',
      'query.q',
      'body.name',
      'body.stages',
    ]);
  });

  it('treats a body that is not an object as one issue at "body"', () => {
    for (const bad of [null, 'text', 5, [], undefined]) {
      expect(
        issuesOf(() => validateInput({ body }, { params: {}, query: {}, body: bad })).map(
          (i) => i.path,
        ),
      ).toEqual(['body']);
    }
  });

  it('does not echo the rejected value in the messages', () => {
    const secret = 'hunter2-super-secret-value';
    const issues = issuesOf(() =>
      validateInput(
        { body: z.object({ age: z.number() }).strict() },
        { params: {}, query: {}, body: { age: secret } },
      ),
    );
    expect(JSON.stringify(issues)).not.toContain(secret);
  });
});

describe('problemBody limits', () => {
  it('caps errors[] at 50 (ValidationProblem.maxItems) and truncates long text', () => {
    const issues = Array.from({ length: 80 }, (_unused, index) => ({
      path: `body.field${index}`,
      message: 'x'.repeat(1000),
    }));
    const body = problemBody({
      code: 'VALIDATION_ERROR',
      requestId: 'req-12345678',
      errors: issues,
    });
    const errors = body['errors'] as { path: string; message: string }[];
    expect(errors).toHaveLength(MAX_PROBLEM_ERRORS);
    expect(errors[0]?.message.length).toBeLessThanOrEqual(200);
  });

  it('truncates detail to the contract maximum of 500 characters', () => {
    const body = problemBody({
      code: 'CONFLICT',
      requestId: 'req-12345678',
      detail: 'd'.repeat(5000),
    });
    expect((body['detail'] as string).length).toBe(500);
  });
});

describe('queryToObject', () => {
  it('maps single keys to strings and repeated keys to arrays', () => {
    expect(queryToObject(new URLSearchParams('a=1&b=2&b=3&c='))).toEqual({
      a: '1',
      b: ['2', '3'],
      c: '',
    });
  });

  it('is safe against prototype keys: they stay plain data and a strict schema rejects them', () => {
    const query = queryToObject(new URLSearchParams('__proto__=x&__proto__=y&constructor=z'));
    expect(Object.getPrototypeOf(query)).toBe(Object.prototype);
    expect(Object.keys(query)).toEqual(['__proto__', 'constructor']);
    expect(({} as Record<string, unknown>)['x']).toBeUndefined();
    expect(z.object({}).strict().safeParse(query).success).toBe(false);
  });
});
