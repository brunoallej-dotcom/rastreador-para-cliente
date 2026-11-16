import type { SupabaseClient } from '@supabase/supabase-js';
import { describe, expect, it, vi } from 'vitest';
import type { Database } from '@/shared/db/database.types';
import {
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  ValidationError,
} from '@/shared/kernel';
import { ClientArchivedError, ProcessNotActiveError } from '../domain/errors';
import { createSupabaseProcessRepository } from './supabase-process-repository';

const CLIENT = '00000000-0000-4000-8000-00000000000a';
const P1 = '00000000-0000-4000-8000-0000000001a1';
const P2 = '00000000-0000-4000-8000-0000000001a2';
const P3 = '00000000-0000-4000-8000-0000000001a3';
const S1 = '00000000-0000-4000-8000-000000000201';
const S2 = '00000000-0000-4000-8000-000000000202';
const CEO = '11111111-1111-4111-8111-111111111111';

const PROCESS_COLUMNS =
  'id, client_id, title, status, version, created_at, updated_at, completed_at, cancelled_at';
const DETAIL_SELECT =
  `${PROCESS_COLUMNS}, client:clients(id, name), ` +
  'stages:process_stages(id, position, name, description, status, started_at, completed_at, ' +
  'approval:stage_approvals(approved_at, approver:profiles(id, display_name)))';
const SUMMARY_SELECT =
  `${PROCESS_COLUMNS}, total_stages:process_stages(count), ` +
  'completed_stages:process_stages(count), current_stage:process_stages(id, position, name)';

type Outcome = { data: unknown; error: unknown; status: number };

const answer = (data: unknown, status = 200): Outcome => ({ data, error: null, status });
const failure = (code: string, message: string, status = 400): Outcome => ({
  data: null,
  error: { code, message },
  status,
});

const AT = '2026-11-16T11:30:24.984084+00:00';

/** A bare process row, as `create_process` and `update_process` return it. */
const writeRowOf = (id: string, title = 'Processo') => ({
  id,
  client_id: CLIENT,
  title,
  status: 'active',
  version: 1,
  created_at: AT,
  updated_at: AT,
  completed_at: null,
  cancelled_at: null,
});

const stageRowOf = (
  id: string,
  position: number,
  status: 'pending' | 'in_progress' | 'completed',
  approval: unknown[] = [],
) => ({
  id,
  position,
  name: `Fase ${position}`,
  description: position === 1 ? 'Detalhe' : null,
  status,
  started_at: status === 'pending' ? null : AT,
  completed_at: status === 'completed' ? AT : null,
  approval,
});

const approvalRow = {
  approved_at: '2026-11-16T12:00:00.500000+00:00',
  approver: { id: CEO, display_name: 'CEO Um' },
};

/** A process with its client and stages, as the detail read returns it. */
const detailRowOf = (id: string, stages: unknown[]) => ({
  ...writeRowOf(id),
  client: { id: CLIENT, name: 'Cliente A' },
  stages,
});

const summaryRowOf = (
  id: string,
  createdAt: string,
  extra: { total?: number; completed?: number; current?: unknown[] } = {},
) => ({
  ...writeRowOf(id, `Processo ${id.slice(-1)}`),
  created_at: createdAt,
  updated_at: createdAt,
  total_stages: [{ count: extra.total ?? 3 }],
  completed_stages: [{ count: extra.completed ?? 0 }],
  current_stage: extra.current ?? [{ id: S1, position: 1, name: 'Fase 1' }],
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
  return { supabase, queries, remaining: () => queue.length };
}

const logger = () => ({ warn: vi.fn() });
const repositoryOver = (outcomes: Outcome[]) => {
  const warn = logger();
  const fake = fakeSupabase(outcomes);
  return {
    repository: createSupabaseProcessRepository(fake.supabase, { logger: warn }),
    warn,
    ...fake,
  };
};

describe('find', () => {
  it('AC-15: reads the detail in one request, explicit columns, stages in order, and maps it', async () => {
    const { repository, queries } = repositoryOver([
      answer(
        detailRowOf(P1, [
          stageRowOf(S2, 2, 'in_progress'),
          stageRowOf(S1, 1, 'completed', [approvalRow]),
        ]),
      ),
    ]);

    const process = await repository.find(P1);

    expect(queries).toEqual([
      [
        ['from', 'processes'],
        ['select', DETAIL_SELECT],
        ['eq', 'id', P1],
        ['order', 'position', { referencedTable: 'stages', ascending: true }],
        ['retry', false],
        ['maybeSingle'],
      ],
    ]);
    expect(process).toMatchObject({
      id: P1,
      clientId: CLIENT,
      client: { id: CLIENT, name: 'Cliente A' },
      status: 'active',
      version: 1,
      createdAt: new Date('2026-11-16T11:30:24.984Z'),
      completedAt: null,
      cancelledAt: null,
    });
    // sorted by position whatever order the database answered in
    expect(process?.stages.map((stage) => stage.position)).toEqual([1, 2]);
    expect(process?.stages[0]).toMatchObject({
      id: S1,
      name: 'Fase 1',
      description: 'Detalhe',
      status: 'completed',
      completedAt: new Date('2026-11-16T11:30:24.984Z'),
      approval: {
        approvedBy: { id: CEO, displayName: 'CEO Um' },
        approvedAt: new Date('2026-11-16T12:00:00.500Z'),
      },
    });
    expect(process?.stages[1]).toMatchObject({ approval: null, completedAt: null });
  });

  it('is null for a process the session cannot see', async () => {
    const { repository } = repositoryOver([answer(null)]);

    expect(await repository.find(P1)).toBeNull();
  });

  it.each([
    ['a row with no stage (I1)', detailRowOf(P1, [])],
    [
      'a row with 31 stages',
      detailRowOf(
        P1,
        Array.from({ length: 31 }, (_v, i) => stageRowOf(S1, (i % 30) + 1, 'pending')),
      ),
    ],
    ['a stage with an unknown status', detailRowOf(P1, [stageRowOf(S1, 1, 'done' as 'pending')])],
    [
      'a stage with two approvals',
      detailRowOf(P1, [stageRowOf(S1, 1, 'completed', [approvalRow, approvalRow])]),
    ],
    [
      'an approval whose CEO is hidden',
      detailRowOf(P1, [stageRowOf(S1, 1, 'completed', [{ ...approvalRow, approver: null }])]),
    ],
    [
      'a row with no client',
      { ...detailRowOf(P1, [stageRowOf(S1, 1, 'in_progress')]), client: null },
    ],
    [
      'a timestamp that is not one',
      { ...detailRowOf(P1, [stageRowOf(S1, 1, 'in_progress')]), created_at: 'yesterday' },
    ],
    ['a row that is not an object', 'not a row'],
  ])('fails closed (an unexpected error, not a response) on %s', async (_label, row) => {
    const { repository } = repositoryOver([answer(row)]);

    const failed = await repository.find(P1).then(
      () => undefined,
      (error: unknown) => error,
    );

    expect(failed).toBeInstanceOf(Error);
    expect(failed).not.toBeInstanceOf(ServiceUnavailableError);
    expect((failed as Error).message).toMatch(/not understood/);
  });

  it('E-21: an unreachable database is a ServiceUnavailableError, not a 500', async () => {
    const { repository } = repositoryOver([failure('', 'fetch failed', 0)]);

    await expect(repository.find(P1)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('an error that is not an outage is an unexpected error, with only code and status as cause', async () => {
    const { repository } = repositoryOver([failure('XX000', 'secret detail: Cliente Acme', 400)]);

    const failed = await repository.find(P1).then(
      () => undefined,
      (error: unknown) => error as Error,
    );

    expect(failed).toBeInstanceOf(Error);
    expect(failed).not.toBeInstanceOf(ServiceUnavailableError);
    expect(failed?.cause).toEqual({ code: 'XX000', status: 400 });
    expect(JSON.stringify(failed?.cause)).not.toContain('Acme');
  });
});

describe('create', () => {
  const stagesOf = (...statuses: ('pending' | 'in_progress')[]) =>
    statuses.map((status, index) => stageRowOf(index === 0 ? S1 : S2, index + 1, status));

  it('AC-15: without stages, calls create_process without p_stages and reads the process back', async () => {
    const { repository, queries } = repositoryOver([
      answer(writeRowOf(P1, 'Site novo')),
      answer(detailRowOf(P1, stagesOf('in_progress', 'pending'))),
    ]);

    const result = await repository.create({ clientId: CLIENT, title: 'Site novo', stages: null });

    expect(queries[0]).toEqual([
      ['rpc', 'create_process', { p_client_id: CLIENT, p_title: 'Site novo' }],
    ]);
    expect(queries[1]?.[0]).toEqual(['from', 'processes']);
    expect(result.ok && result.value.stages).toHaveLength(2);
  });

  it('AC-15: with stages, sends them as name and description, in order', async () => {
    const { repository, queries } = repositoryOver([
      answer(writeRowOf(P1)),
      answer(detailRowOf(P1, stagesOf('in_progress', 'pending'))),
    ]);

    await repository.create({
      clientId: CLIENT,
      title: 'Loja',
      stages: [
        { name: 'Desenho', description: 'Telas' },
        { name: 'Entrega', description: null },
      ],
    });

    expect(queries[0]).toEqual([
      [
        'rpc',
        'create_process',
        {
          p_client_id: CLIENT,
          p_title: 'Loja',
          p_stages: [
            { name: 'Desenho', description: 'Telas' },
            { name: 'Entrega', description: null },
          ],
        },
      ],
    ]);
  });

  it.each([
    [
      'E-16: an archived client',
      failure('P0001', 'CLIENT_ARCHIVED'),
      ClientArchivedError,
      'CLIENT_ARCHIVED',
    ],
    ['an unknown client', failure('P0001', 'NOT_FOUND'), NotFoundError, 'NOT_FOUND'],
    ['invalid input', failure('P0001', 'INVALID_INPUT'), ValidationError, 'VALIDATION_ERROR'],
    [
      'a check violation',
      failure('23514', 'new row violates a check'),
      ValidationError,
      'VALIDATION_ERROR',
    ],
    ['a value too long', failure('22001', 'value too long'), ValidationError, 'VALIDATION_ERROR'],
    ['a denial', failure('42501', 'FORBIDDEN'), ForbiddenError, 'FORBIDDEN'],
  ])('maps %s to its domain error and reads nothing back', async (_label, outcome, type, code) => {
    const { repository, queries } = repositoryOver([outcome]);

    const result = await repository.create({ clientId: CLIENT, title: 'Loja', stages: null });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(type);
    expect(result.error.code).toBe(code);
    expect(queries).toHaveLength(1);
  });

  it('a client that is not there names the client in the 404, not a process', async () => {
    const { repository } = repositoryOver([failure('P0001', 'NOT_FOUND')]);

    const result = await repository.create({ clientId: CLIENT, title: 'Loja', stages: null });

    expect(!result.ok && result.error.detail).toBe('Client not found.');
  });

  it('a denial is logged as a bypass of layer 1 and carries no detail of the database', async () => {
    const { repository, warn } = repositoryOver([failure('42501', 'FORBIDDEN: Cliente Acme')]);

    const result = await repository.create({ clientId: CLIENT, title: 'Loja', stages: null });

    expect(warn.warn).toHaveBeenCalledWith(
      { event: 'authz.database_denied', operation: 'create_process' },
      'authz.database_denied',
    );
    expect(!result.ok && result.error.detail).toBe('Access denied.');
  });

  it.each(['40P01', '40001'])(
    'E-21: %s (the transaction was rolled back) is a 503 whatever the HTTP status, with only code and status as cause',
    async (code) => {
      for (const httpStatus of [500, 409, 400]) {
        const { repository } = repositoryOver([
          failure(code, 'deadlock detected: Cliente Acme', httpStatus),
        ]);

        const failed = await repository
          .create({ clientId: CLIENT, title: 'Loja', stages: null })
          .then(
            () => undefined,
            (error: unknown) => error as Error,
          );

        expect(failed).toBeInstanceOf(ServiceUnavailableError);
        expect(failed?.cause).toEqual({ code, status: httpStatus });
      }
    },
  );

  it('E-21: a database that cannot be reached is a ServiceUnavailableError', async () => {
    const { repository } = repositoryOver([failure('', 'fetch failed', 0)]);

    await expect(
      repository.create({ clientId: CLIENT, title: 'Loja', stages: null }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('an unmapped error, a raw 23505 included, is an unexpected error (500)', async () => {
    for (const outcome of [failure('23505', 'duplicate key'), failure('P0001', 'TEMPLATE_EMPTY')]) {
      const { repository } = repositoryOver([outcome]);

      const failed = await repository
        .create({ clientId: CLIENT, title: 'Loja', stages: null })
        .then(
          () => undefined,
          (error: unknown) => error,
        );

      expect(failed).toBeInstanceOf(Error);
      expect(failed).not.toBeInstanceOf(ServiceUnavailableError);
    }
  });

  it('fails closed when the function answers a row that is not understood', async () => {
    const { repository } = repositoryOver([answer({ id: 'not-a-uuid' })]);

    await expect(
      repository.create({ clientId: CLIENT, title: 'Loja', stages: null }),
    ).rejects.toThrow(/not understood/);
  });

  it('E-21: a process saved and then lost from sight (the session ended) is a 404, not a 500', async () => {
    const { repository } = repositoryOver([answer(writeRowOf(P1)), answer(null)]);

    const result = await repository.create({ clientId: CLIENT, title: 'Loja', stages: null });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(NotFoundError);
  });

  it('E-21: a process saved whose read back cannot reach the database is a 503', async () => {
    const { repository } = repositoryOver([answer(writeRowOf(P1)), failure('', 'fetch failed', 0)]);

    await expect(
      repository.create({ clientId: CLIENT, title: 'Loja', stages: null }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});

describe('update', () => {
  it('AC-19: sends only the fields of the patch and reads the process back', async () => {
    const { repository, queries } = repositoryOver([
      answer(writeRowOf(P1)),
      answer(detailRowOf(P1, [stageRowOf(S1, 1, 'in_progress')])),
    ]);

    await repository.update(P1, { title: 'Novo' });
    const second = repositoryOver([
      answer(writeRowOf(P1)),
      answer(detailRowOf(P1, [stageRowOf(S1, 1, 'in_progress')])),
    ]);
    await second.repository.update(P1, { cancel: true });
    const third = repositoryOver([
      answer(writeRowOf(P1)),
      answer(detailRowOf(P1, [stageRowOf(S1, 1, 'in_progress')])),
    ]);
    await third.repository.update(P1, { title: 'Novo', cancel: true });

    expect(queries[0]).toEqual([['rpc', 'update_process', { p_process_id: P1, p_title: 'Novo' }]]);
    expect(second.queries[0]).toEqual([
      ['rpc', 'update_process', { p_process_id: P1, p_cancel: true }],
    ]);
    expect(third.queries[0]).toEqual([
      ['rpc', 'update_process', { p_process_id: P1, p_title: 'Novo', p_cancel: true }],
    ]);
  });

  it.each([
    [
      'AC-19: a completed or cancelled process',
      failure('P0001', 'PROCESS_NOT_ACTIVE'),
      ProcessNotActiveError,
      'PROCESS_NOT_ACTIVE',
    ],
    ['an unknown process', failure('P0001', 'NOT_FOUND'), NotFoundError, 'NOT_FOUND'],
    ['invalid input', failure('P0001', 'INVALID_INPUT'), ValidationError, 'VALIDATION_ERROR'],
    ['a denial', failure('42501', 'FORBIDDEN'), ForbiddenError, 'FORBIDDEN'],
  ])('maps %s to its domain error', async (_label, outcome, type, code) => {
    const { repository, queries } = repositoryOver([outcome]);

    const result = await repository.update(P1, { title: 'Novo' });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(type);
    expect(result.error.code).toBe(code);
    expect(queries).toHaveLength(1);
  });

  it('a process that is not there names the process in the 404', async () => {
    const { repository } = repositoryOver([failure('P0001', 'NOT_FOUND')]);

    const result = await repository.update(P1, { title: 'Novo' });

    expect(!result.ok && result.error.detail).toBe('Process not found.');
  });

  it('E-21: a rolled back transaction is a 503 and an unreachable database too', async () => {
    const rolledBack = repositoryOver([failure('40P01', 'deadlock detected', 500)]);
    const down = repositoryOver([failure('', 'fetch failed', 0)]);

    await expect(rolledBack.repository.update(P1, { title: 'Novo' })).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
    await expect(down.repository.update(P1, { title: 'Novo' })).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it('a process that cannot be read after the write is a 404', async () => {
    const { repository } = repositoryOver([answer(writeRowOf(P1)), answer(null)]);

    const result = await repository.update(P1, { title: 'Novo' });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(NotFoundError);
  });
});

describe('listByClient', () => {
  const FIRST = '2026-11-16T11:00:00.000003+00:00';
  const SECOND = '2026-11-16T10:00:00.000002+00:00';
  const THIRD = '2026-11-16T09:00:00.000001+00:00';

  it('AC-15: the first page is one query, explicit columns, newest first, with a lookahead row', async () => {
    const { repository, queries } = repositoryOver([
      answer([summaryRowOf(P1, FIRST, { completed: 1 })]),
    ]);

    const page = await repository.listByClient(CLIENT, { limit: 10 });

    expect(queries).toEqual([
      [
        ['from', 'processes'],
        ['select', SUMMARY_SELECT],
        ['eq', 'client_id', CLIENT],
        ['eq', 'completed_stages.status', 'completed'],
        ['eq', 'current_stage.status', 'in_progress'],
        ['retry', false],
        ['order', 'created_at', { ascending: false }],
        ['order', 'id', { ascending: true }],
        ['limit', 11],
      ],
    ]);
    expect(page?.next).toBeNull();
    expect(page?.items).toEqual([
      {
        id: P1,
        clientId: CLIENT,
        title: 'Processo 1',
        status: 'active',
        currentStage: { id: S1, position: 1, name: 'Fase 1' },
        totalStages: 3,
        completedStages: 1,
        version: 1,
        createdAt: new Date('2026-11-16T11:00:00.000Z'),
        updatedAt: new Date('2026-11-16T11:00:00.000Z'),
        completedAt: null,
        cancelledAt: null,
      },
    ]);
  });

  it('AC-15: a status filter narrows the query by status', async () => {
    const { repository, queries } = repositoryOver([answer([summaryRowOf(P1, FIRST)])]);

    await repository.listByClient(CLIENT, { limit: 10, status: 'cancelled' });

    expect(queries[0]).toContainEqual(['eq', 'status', 'cancelled']);
  });

  it('a process with no stage in progress has no current stage', async () => {
    const { repository } = repositoryOver([
      answer([summaryRowOf(P1, FIRST, { total: 2, completed: 2, current: [] })]),
    ]);

    const page = await repository.listByClient(CLIENT, { limit: 10 });

    expect(page?.items[0]).toMatchObject({
      currentStage: null,
      totalStages: 2,
      completedStages: 2,
    });
  });

  it('a full page reports where to resume: the last row, with the exact timestamp text', async () => {
    const { repository } = repositoryOver([
      answer([summaryRowOf(P1, FIRST), summaryRowOf(P2, SECOND), summaryRowOf(P3, THIRD)]),
    ]);

    const page = await repository.listByClient(CLIENT, { limit: 2 });

    expect(page?.items.map((item) => item.id)).toEqual([P1, P2]);
    expect(page?.next).toEqual({ createdAt: SECOND, id: P2 });
  });

  it('the next page is two plain queries: the same instant with a larger id, then the older ones', async () => {
    const { repository, queries } = repositoryOver([
      answer([summaryRowOf(P2, SECOND)]),
      answer([summaryRowOf(P3, THIRD)]),
    ]);

    const page = await repository.listByClient(CLIENT, {
      limit: 5,
      after: { createdAt: SECOND, id: '00000000-0000-4000-8000-0000000001a0' },
    });

    expect(queries[0]).toEqual([
      ['from', 'processes'],
      ['select', SUMMARY_SELECT],
      ['eq', 'client_id', CLIENT],
      ['eq', 'completed_stages.status', 'completed'],
      ['eq', 'current_stage.status', 'in_progress'],
      ['retry', false],
      ['eq', 'created_at', SECOND],
      ['gt', 'id', '00000000-0000-4000-8000-0000000001a0'],
      ['order', 'id', { ascending: true }],
      ['limit', 6],
    ]);
    expect(queries[1]).toContainEqual(['lt', 'created_at', SECOND]);
    expect(queries[1]).toContainEqual(['limit', 5]);
    expect(page?.items.map((item) => item.id)).toEqual([P2, P3]);
  });

  it('skips the second query when the first already filled the page', async () => {
    const { repository, queries, remaining } = repositoryOver([
      answer([summaryRowOf(P2, SECOND), summaryRowOf(P3, SECOND)]),
    ]);

    const page = await repository.listByClient(CLIENT, {
      limit: 1,
      after: { createdAt: SECOND, id: '00000000-0000-4000-8000-0000000001a0' },
    });

    expect(queries).toHaveLength(1);
    expect(remaining()).toBe(0);
    expect(page?.items.map((item) => item.id)).toEqual([P2]);
    expect(page?.next).toEqual({ createdAt: SECOND, id: P2 });
  });

  it('an empty answer for a client that exists is an empty page', async () => {
    const { repository, queries } = repositoryOver([
      answer([]),
      answer({ id: CLIENT, name: 'Cliente A', archived_at: null }),
    ]);

    const page = await repository.listByClient(CLIENT, { limit: 10 });

    expect(page).toEqual({ items: [], next: null });
    expect(queries[1]?.[0]).toEqual(['from', 'clients']);
  });

  it('an empty answer for a client that is not there (or not visible) is null: a 404', async () => {
    const { repository } = repositoryOver([answer([]), answer(null)]);

    expect(await repository.listByClient(CLIENT, { limit: 10 })).toBeNull();
  });

  it('a row proves the client exists: no extra read when there are rows', async () => {
    const { repository, queries } = repositoryOver([answer([summaryRowOf(P1, FIRST)])]);

    await repository.listByClient(CLIENT, { limit: 10 });

    expect(queries).toHaveLength(1);
  });

  it('F-53: a position the database cannot read (class 22) is a 400 on query.cursor', async () => {
    const { repository } = repositoryOver([failure('22008', 'date/time field value out of range')]);

    const failed = await repository
      .listByClient(CLIENT, { limit: 5, after: { createdAt: SECOND, id: P1 } })
      .then(
        () => undefined,
        (error: unknown) => error as ValidationError,
      );

    expect(failed).toBeInstanceOf(ValidationError);
    expect(failed?.issues).toEqual([{ path: 'query.cursor', message: 'Invalid cursor' }]);
    expect(failed?.cause).toEqual({ code: '22008' });
  });

  it('a class 22 error with no position given is not the cursor: an unexpected error', async () => {
    const { repository } = repositoryOver([failure('22008', 'out of range')]);

    const failed = await repository.listByClient(CLIENT, { limit: 5 }).then(
      () => undefined,
      (error: unknown) => error,
    );

    expect(failed).toBeInstanceOf(Error);
    expect(failed).not.toBeInstanceOf(ValidationError);
  });

  it('E-21: an unreachable database is a ServiceUnavailableError, on either query', async () => {
    const first = repositoryOver([failure('', 'fetch failed', 0)]);
    const second = repositoryOver([answer([]), failure('', 'fetch failed', 0)]);

    await expect(first.repository.listByClient(CLIENT, { limit: 5 })).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
    await expect(
      second.repository.listByClient(CLIENT, {
        limit: 5,
        after: { createdAt: SECOND, id: P1 },
      }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it.each([
    ['a process with no stage (a count of zero)', summaryRowOf(P1, FIRST, { total: 0 })],
    [
      'two current stages',
      summaryRowOf(P1, FIRST, {
        current: [
          { id: S1, position: 1, name: 'A' },
          { id: S2, position: 2, name: 'B' },
        ],
      }),
    ],
    [
      'a count that is not a count',
      { ...summaryRowOf(P1, FIRST), completed_stages: [{ count: 'x' }] },
    ],
    ['a status the process cannot have', { ...summaryRowOf(P1, FIRST), status: 'archived' }],
  ])('fails closed on %s', async (_label, row) => {
    const { repository } = repositoryOver([answer([row])]);

    await expect(repository.listByClient(CLIENT, { limit: 5 })).rejects.toThrow(/not understood/);
  });
});

describe('defaultStageTemplate', () => {
  it('AC-15: reads the template in position order, explicit columns', async () => {
    const { repository, queries } = repositoryOver([
      answer([
        { position: 1, name: 'Contrato', description: null },
        { position: 2, name: 'Briefing', description: 'Levantamento' },
      ]),
    ]);

    const template = await repository.defaultStageTemplate();

    expect(queries).toEqual([
      [
        ['from', 'default_stage_template'],
        ['select', 'position, name, description'],
        ['order', 'position', { ascending: true }],
        ['retry', false],
      ],
    ]);
    expect(template).toEqual({
      stages: [
        { position: 1, name: 'Contrato', description: null },
        { position: 2, name: 'Briefing', description: 'Levantamento' },
      ],
    });
  });

  it('fails closed on an empty template or a row that is not understood', async () => {
    for (const data of [[], [{ position: 0, name: 'A', description: null }], 'nope']) {
      const { repository } = repositoryOver([answer(data)]);

      await expect(repository.defaultStageTemplate()).rejects.toThrow(/not understood/);
    }
  });

  it('E-21: an unreachable database is a ServiceUnavailableError', async () => {
    const { repository } = repositoryOver([failure('', 'fetch failed', 0)]);

    await expect(repository.defaultStageTemplate()).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
