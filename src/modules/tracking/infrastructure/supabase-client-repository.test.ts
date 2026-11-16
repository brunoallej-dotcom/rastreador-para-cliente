import type { SupabaseClient } from '@supabase/supabase-js';
import { describe, expect, it, vi } from 'vitest';
import type { Database } from '@/shared/db/database.types';
import {
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  ValidationError,
} from '@/shared/kernel';
import { createSupabaseClientRepository } from './supabase-client-repository';

const A = '00000000-0000-4000-8000-00000000000a';
const B = '00000000-0000-4000-8000-00000000000b';
const C = '00000000-0000-4000-8000-00000000000c';

const CLIENT_SELECT =
  'id, name, archived_at, created_at, updated_at, all_processes:processes(count), active_processes:processes(count)';

type Outcome = { data: unknown; error: unknown; status: number };

const answer = (data: unknown, status = 200): Outcome => ({ data, error: null, status });
const failure = (code: string, message: string, status = 400): Outcome => ({
  data: null,
  error: { code, message },
  status,
});

const rowOf = (
  id: string,
  createdAt: string,
  extra: { name?: string; archivedAt?: string | null; all?: number; active?: number } = {},
) => ({
  id,
  name: extra.name ?? `Cliente ${id.slice(-1)}`,
  archived_at: extra.archivedAt ?? null,
  created_at: createdAt,
  updated_at: createdAt,
  all_processes: [{ count: extra.all ?? 0 }],
  active_processes: [{ count: extra.active ?? 0 }],
});

/** A bare client row, as `create_client` and `update_client` return it (no counters). */
const writeRowOf = (id: string, name: string) => ({
  id,
  name,
  archived_at: null,
  created_at: '2026-11-16T11:30:24.984084+00:00',
  updated_at: '2026-11-16T11:30:24.984084+00:00',
});

/**
 * Records every call of a query chain and answers the scripted outcomes in order, one per awaited
 * query or rpc. Any method of the chain is accepted: what matters is what was called.
 */
function fakeSupabase(outcomes: Outcome[]) {
  const queue = [...outcomes];
  const queries: unknown[][][] = [];
  const next = () => {
    const outcome = queue.shift();
    if (outcome === undefined) throw new Error('the test scripted fewer outcomes than calls');
    return outcome;
  };

  const chain = (calls: unknown[][]): unknown => {
    const proxy: unknown = new Proxy(
      {},
      {
        get: (_target, method) => {
          if (method === 'then') {
            return (resolve: (value: Outcome) => void) => resolve(next());
          }
          return (...args: unknown[]) => {
            calls.push([String(method), ...args]);
            if (method === 'maybeSingle') return Promise.resolve(next());
            return proxy;
          };
        },
      },
    );
    return proxy;
  };

  const supabase = {
    from: (table: string) => {
      const calls: unknown[][] = [['from', table]];
      queries.push(calls);
      return chain(calls);
    },
    rpc: (name: string, args: unknown) => {
      const calls: unknown[][] = [['rpc', name, args]];
      queries.push(calls);
      return chain(calls);
    },
  } as unknown as SupabaseClient<Database>;
  return { supabase, queries };
}

const logger = () => ({ warn: vi.fn() });

describe('list', () => {
  it('AC-11: the first page is one query, explicit columns, newest first, with a lookahead row', async () => {
    const { supabase, queries } = fakeSupabase([
      answer([rowOf(A, '2026-11-16T11:00:00.000001+00:00', { all: 3, active: 2 })]),
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const page = await repository.list({ limit: 10, includeArchived: false });

    expect(queries).toEqual([
      [
        ['from', 'clients'],
        ['select', CLIENT_SELECT],
        ['eq', 'active_processes.status', 'active'],
        ['retry', false],
        ['is', 'archived_at', null],
        ['order', 'created_at', { ascending: false }],
        ['order', 'id', { ascending: true }],
        ['limit', 11],
      ],
    ]);
    expect(page.next).toBeNull();
    expect(page.items).toEqual([
      {
        id: A,
        name: 'Cliente a',
        archivedAt: null,
        activeProcessCount: 2,
        processCount: 3,
        createdAt: new Date('2026-11-16T11:00:00.000Z'),
        updatedAt: new Date('2026-11-16T11:00:00.000Z'),
      },
    ]);
  });

  it('AC-11: includeArchived drops the archived filter', async () => {
    const { supabase, queries } = fakeSupabase([
      answer([
        rowOf(A, '2026-11-16T11:00:00.000001+00:00', { archivedAt: '2026-11-16T12:00:00+00:00' }),
      ]),
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const page = await repository.list({ limit: 10, includeArchived: true });

    expect(queries[0]?.map((call) => call[0])).not.toContain('is');
    expect(page.items[0]?.archivedAt).toEqual(new Date('2026-11-16T12:00:00Z'));
  });

  it('AC-11: a lookahead row makes a next position out of the last row of the page, raw timestamp kept', async () => {
    const stamp = '2026-11-16T11:00:00.123456+00:00';
    const { supabase } = fakeSupabase([
      answer([rowOf(A, stamp), rowOf(B, '2026-11-16T10:00:00.000002+00:00')]),
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const page = await repository.list({ limit: 1, includeArchived: false });

    expect(page.items.map((item) => item.id)).toEqual([A]);
    expect(page.next).toEqual({ createdAt: stamp, id: A });
  });

  it('AC-11: after a position, the same-instant tail comes first, then the older rows', async () => {
    const stamp = '2026-11-16T11:00:00.123456+00:00';
    const older = '2026-11-16T10:00:00.000002+00:00';
    const { supabase, queries } = fakeSupabase([
      answer([rowOf(B, stamp)]),
      answer([rowOf(C, older)]),
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const page = await repository.list({
      limit: 5,
      includeArchived: false,
      after: { createdAt: stamp, id: A },
    });

    expect(page.items.map((item) => item.id)).toEqual([B, C]);
    expect(page.next).toBeNull();
    expect(queries).toHaveLength(2);
    expect(queries[0]).toContainEqual(['eq', 'created_at', stamp]);
    expect(queries[0]).toContainEqual(['gt', 'id', A]);
    expect(queries[0]).toContainEqual(['order', 'id', { ascending: true }]);
    expect(queries[0]).toContainEqual(['limit', 6]);
    expect(queries[1]).toContainEqual(['lt', 'created_at', stamp]);
    expect(queries[1]).toContainEqual(['limit', 5]);
  });

  it('AC-11: a full same-instant tail needs no second query', async () => {
    const stamp = '2026-11-16T11:00:00.123456+00:00';
    const { supabase, queries } = fakeSupabase([answer([rowOf(B, stamp), rowOf(C, stamp)])]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const page = await repository.list({
      limit: 1,
      includeArchived: false,
      after: { createdAt: stamp, id: A },
    });

    expect(queries).toHaveLength(1);
    expect(page.items.map((item) => item.id)).toEqual([B]);
    expect(page.next).toEqual({ createdAt: stamp, id: B });
  });

  it('SEC-06: never builds a filter out of a value (.or, .filter and .textSearch stay unused)', async () => {
    const stamp = '2026-11-16T11:00:00.123456+00:00';
    const { supabase, queries } = fakeSupabase([answer([]), answer([])]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    await repository.list({ limit: 5, includeArchived: false, after: { createdAt: stamp, id: A } });

    const methods = queries.flat().map((call) => call[0]);
    expect(methods).not.toContain('or');
    expect(methods).not.toContain('filter');
    expect(methods).not.toContain('textSearch');
  });

  it('E-21: Supabase being down is ServiceUnavailableError', async () => {
    const { supabase } = fakeSupabase([
      { data: null, error: { message: 'TypeError: fetch failed', code: '' }, status: 0 },
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    await expect(repository.list({ limit: 5, includeArchived: false })).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it.each([
    [
      'a row without counters',
      [{ ...rowOf(A, '2026-11-16T11:00:00.000001+00:00'), all_processes: [] }],
    ],
    ['an id that is not a UUID', [rowOf('nope', '2026-11-16T11:00:00.000001+00:00')]],
    ['a timestamp without an offset', [rowOf(A, '2026-11-16 11:00:00')]],
    ['a negative counter', [rowOf(A, '2026-11-16T11:00:00.000001+00:00', { all: -1 })]],
    ['something that is not a list', { id: A }],
  ])('fails closed on %s', async (_label, data) => {
    const { supabase } = fakeSupabase([answer(data)]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    await expect(repository.list({ limit: 5, includeArchived: false })).rejects.toThrow(
      'not understood',
    );
  });

  it('denies on any other database error, without echoing it', async () => {
    const { supabase } = fakeSupabase([failure('XX000', 'internal detail 12345', 400)]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const rejection = repository.list({ limit: 5, includeArchived: false });
    await expect(rejection).rejects.not.toBeInstanceOf(ServiceUnavailableError);
    await expect(rejection).rejects.toThrow('list the clients failed unexpectedly');
    await expect(rejection).rejects.not.toThrow('12345');
  });
});

describe('find', () => {
  it('AC-11: reads one client by id with the counters, and no retry', async () => {
    const { supabase, queries } = fakeSupabase([
      answer(rowOf(A, '2026-11-16T11:00:00.000001+00:00', { all: 4, active: 1 })),
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const client = await repository.find(A);

    expect(queries).toEqual([
      [
        ['from', 'clients'],
        ['select', CLIENT_SELECT],
        ['eq', 'id', A],
        ['eq', 'active_processes.status', 'active'],
        ['retry', false],
        ['maybeSingle'],
      ],
    ]);
    expect(client).toMatchObject({ id: A, activeProcessCount: 1, processCount: 4 });
  });

  it('SEC-05: a row RLS hides is null, not an error', async () => {
    const { supabase } = fakeSupabase([answer(null)]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    await expect(repository.find(A)).resolves.toBeNull();
  });

  it('E-21: Supabase being down is ServiceUnavailableError', async () => {
    const { supabase } = fakeSupabase([
      { data: null, error: { message: 'TypeError: fetch failed', code: '' }, status: 0 },
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    await expect(repository.find(A)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('fails closed on a row it does not understand', async () => {
    const { supabase } = fakeSupabase([answer({ id: A })]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    await expect(repository.find(A)).rejects.toThrow('not understood');
  });
});

describe('create', () => {
  it('AC-11: calls create_client with the name and answers a client with no processes', async () => {
    const { supabase, queries } = fakeSupabase([answer(writeRowOf(A, 'Acme'))]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const result = await repository.create('Acme');

    expect(queries).toEqual([[['rpc', 'create_client', { p_name: 'Acme' }]]]);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toMatchObject({
        id: A,
        name: 'Acme',
        archivedAt: null,
        activeProcessCount: 0,
        processCount: 0,
      });
    }
  });

  it('spec §3.7: 42501 is a ForbiddenError and a warning (the pipeline was bypassed)', async () => {
    const log = logger();
    const { supabase } = fakeSupabase([failure('42501', 'FORBIDDEN', 403)]);
    const repository = createSupabaseClientRepository(supabase, { logger: log });

    const result = await repository.create('Acme');

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(log.warn).toHaveBeenCalledWith(
      { event: 'authz.database_denied', operation: 'create_client' },
      'authz.database_denied',
    );
  });

  it.each([
    ['P0001', 'INVALID_INPUT'],
    ['23514', 'new row violates check constraint'],
    ['22001', 'value too long'],
  ])('spec §3.7: %s (%s) is a ValidationError', async (code, message) => {
    const { supabase } = fakeSupabase([failure(code, message)]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const result = await repository.create('Acme');

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(ValidationError);
      expect(result.error.detail).toBeUndefined();
    }
  });

  it('spec §3.7: what is not mapped is thrown (a 500), not shown', async () => {
    const { supabase } = fakeSupabase([failure('P0001', 'STALE_STAGE', 400)]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    await expect(repository.create('Acme')).rejects.toThrow('create_client failed unexpectedly');
  });

  it('E-21: Supabase being down is ServiceUnavailableError', async () => {
    const { supabase } = fakeSupabase([
      { data: null, error: { message: 'TypeError: fetch failed', code: '' }, status: 0 },
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    await expect(repository.create('Acme')).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('fails closed on a row it does not understand', async () => {
    const { supabase } = fakeSupabase([answer([writeRowOf(A, 'Acme')])]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    await expect(repository.create('Acme')).rejects.toThrow('not understood');
  });
});

describe('update', () => {
  it('AC-11: sends only the fields of the patch, then reads the client again for its counters', async () => {
    const { supabase, queries } = fakeSupabase([
      answer(writeRowOf(A, 'Novo')),
      answer(rowOf(A, '2026-11-16T11:30:24.984084+00:00', { name: 'Novo', all: 2, active: 1 })),
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const result = await repository.update(A, { name: 'Novo' });

    expect(queries[0]).toEqual([['rpc', 'update_client', { p_client_id: A, p_name: 'Novo' }]]);
    expect(queries[1]).toContainEqual(['eq', 'id', A]);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value).toMatchObject({ name: 'Novo', activeProcessCount: 1, processCount: 2 });
    }
  });

  it('AC-11: archived false is sent (it is a change), a missing field is not', async () => {
    const { supabase, queries } = fakeSupabase([
      answer(writeRowOf(A, 'Acme')),
      answer(rowOf(A, '2026-11-16T11:30:24.984084+00:00')),
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    await repository.update(A, { archived: false });

    expect(queries[0]).toEqual([['rpc', 'update_client', { p_client_id: A, p_archived: false }]]);
  });

  it('spec §3.7: NOT_FOUND is a NotFoundError (404) and nothing is read again', async () => {
    const { supabase, queries } = fakeSupabase([failure('P0001', 'NOT_FOUND')]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const result = await repository.update(A, { name: 'Novo' });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(NotFoundError);
      expect(result.error.detail).toBe('Client not found.');
    }
    expect(queries).toHaveLength(1);
  });

  it('F-57: a client that cannot be read right after a good update is a 404, not a 500', async () => {
    const { supabase } = fakeSupabase([answer(writeRowOf(A, 'Novo')), answer(null)]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const result = await repository.update(A, { name: 'Novo' });

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(NotFoundError);
      expect(result.error.detail).toBe('Client not found.');
    }
  });

  it('spec §3.7: 42501 is a ForbiddenError and a warning', async () => {
    const log = logger();
    const { supabase } = fakeSupabase([failure('42501', 'FORBIDDEN', 403)]);
    const repository = createSupabaseClientRepository(supabase, { logger: log });

    const result = await repository.update(A, { archived: true });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(log.warn).toHaveBeenCalledWith(
      { event: 'authz.database_denied', operation: 'update_client' },
      'authz.database_denied',
    );
  });

  it('spec §3.7: INVALID_INPUT is a ValidationError', async () => {
    const { supabase } = fakeSupabase([failure('P0001', 'INVALID_INPUT')]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const result = await repository.update(A, { name: 'Novo' });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ValidationError);
  });

  it('E-21: Supabase being down is ServiceUnavailableError', async () => {
    const { supabase } = fakeSupabase([
      { data: null, error: { message: 'TypeError: fetch failed', code: '' }, status: 0 },
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    await expect(repository.update(A, { name: 'Novo' })).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });
});

describe('a cursor the database cannot read (F-53)', () => {
  const stamp = '2026-11-16T11:00:00.123456+00:00';
  const after = { createdAt: stamp, id: A };

  it.each(['22007', '22008', '22009', '22P02'])(
    'SQLSTATE %s on the first query is a 400 on query.cursor, not a 500',
    async (code) => {
      const { supabase } = fakeSupabase([failure(code, 'time zone displacement out of range')]);
      const repository = createSupabaseClientRepository(supabase, { logger: logger() });

      const rejection = repository.list({ limit: 5, includeArchived: false, after });

      await expect(rejection).rejects.toBeInstanceOf(ValidationError);
      await expect(rejection).rejects.toMatchObject({
        code: 'VALIDATION_ERROR',
        issues: [{ path: 'query.cursor', message: 'Invalid cursor' }],
      });
    },
  );

  it('the same on the second query (the older rows)', async () => {
    const { supabase } = fakeSupabase([
      answer([]),
      failure('22008', 'date/time field value out of range'),
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    await expect(
      repository.list({ limit: 5, includeArchived: false, after }),
    ).rejects.toBeInstanceOf(ValidationError);
  });

  it("a class-22 error with no position (the first page) is not the caller's fault: 500", async () => {
    const { supabase } = fakeSupabase([failure('22008', 'date/time field value out of range')]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const rejection = repository.list({ limit: 5, includeArchived: false });

    await expect(rejection).rejects.not.toBeInstanceOf(ValidationError);
    await expect(rejection).rejects.toThrow('list the clients failed unexpectedly');
  });

  it('another database error with a position stays a 500', async () => {
    const { supabase } = fakeSupabase([failure('XX000', 'internal detail', 400)]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const rejection = repository.list({ limit: 5, includeArchived: false, after });

    await expect(rejection).rejects.not.toBeInstanceOf(ValidationError);
    await expect(rejection).rejects.toThrow('list the clients failed unexpectedly');
  });

  it('keeps no message in the cause of the error it throws', async () => {
    const { supabase } = fakeSupabase([failure('22008', 'detail with the cursor 2026-11-16')]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const error: unknown = await repository
      .list({ limit: 5, includeArchived: false, after })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ValidationError);
    expect((error as ValidationError).cause).toEqual({ code: '22008' });
  });
});

describe('what the database says about a row never travels in a cause', () => {
  // The logger writes the `cause` chain of every 5xx error: a name in it would reach the logs.
  const ROW_MESSAGE = 'null value in column "x"; Failing row contains (11, Cliente Secreto Ltda)';

  const causeOf = (error: unknown) => (error as { cause?: unknown }).cause;

  it('an unmapped write error keeps only the SQLSTATE and the status', async () => {
    const { supabase } = fakeSupabase([
      {
        data: null,
        error: { code: '23502', message: ROW_MESSAGE, details: ROW_MESSAGE },
        status: 400,
      },
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const error: unknown = await repository.create('Acme').catch((caught: unknown) => caught);

    expect(causeOf(error)).toEqual({ code: '23502', status: 400 });
    expect(JSON.stringify(causeOf(error))).not.toContain('Secreto');
  });

  it('a refused write (a ValidationError) keeps only the SQLSTATE', async () => {
    const { supabase } = fakeSupabase([
      { data: null, error: { code: '23514', message: ROW_MESSAGE }, status: 400 },
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const result = await repository.create('Acme');

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(ValidationError);
      expect(causeOf(result.error)).toEqual({ code: '23514' });
    }
  });

  it('an unmapped read error keeps only the SQLSTATE and the status', async () => {
    const { supabase } = fakeSupabase([
      { data: null, error: { code: 'XX000', message: ROW_MESSAGE }, status: 400 },
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    const error: unknown = await repository.find(A).catch((caught: unknown) => caught);

    expect(causeOf(error)).toEqual({ code: 'XX000', status: 400 });
  });

  it('an outage is still told apart (503) after the cause was reduced', async () => {
    const { supabase } = fakeSupabase([
      { data: null, error: { code: '', message: 'TypeError: fetch failed' }, status: 0 },
    ]);
    const repository = createSupabaseClientRepository(supabase, { logger: logger() });

    await expect(repository.create('Acme')).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
