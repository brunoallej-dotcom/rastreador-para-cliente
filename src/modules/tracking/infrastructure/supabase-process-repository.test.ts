import type { SupabaseClient } from '@supabase/supabase-js';
import { describe, expect, it, vi } from 'vitest';
import type { Database } from '@/shared/db/database.types';
import {
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  ValidationError,
} from '@/shared/kernel';
import { ClientArchivedError, ProcessNotActiveError, StaleStageError } from '../domain/errors';
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
/** Creation instants of the rows of a list, newest first. */
const FIRST = '2026-11-16T11:00:00.000003+00:00';
const SECOND = '2026-11-16T10:00:00.000002+00:00';
const THIRD = '2026-11-16T09:00:00.000001+00:00';

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
  extra: {
    total?: number;
    completed?: number;
    current?: unknown[];
    status?: string;
    completedAt?: string | null;
    cancelledAt?: string | null;
  } = {},
) => ({
  ...writeRowOf(id, `Processo ${id.slice(-1)}`),
  status: extra.status ?? 'active',
  completed_at: extra.completedAt ?? null,
  cancelled_at: extra.cancelledAt ?? null,
  created_at: createdAt,
  updated_at: createdAt,
  total_stages: [{ count: extra.total ?? 3 }],
  completed_stages: [{ count: extra.completed ?? 0 }],
  // a healthy active process: the stage after the completed ones is the current one
  current_stage: extra.current ?? [
    { id: S1, position: (extra.completed ?? 0) + 1, name: 'Fase 1' },
  ],
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

const logger = () => ({ warn: vi.fn(), error: vi.fn() });
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

  it.each([
    [
      '23514',
      'a check violation',
      'new row for relation "process_stages" violates a check: Cliente Acme',
    ],
    ['22001', 'a value too long', 'value too long for type character varying(120): Cliente Acme'],
  ])(
    'F-86: %s (%s) is an unexpected error (500), not a 400 that blames the CEO, with only code and status as cause',
    async (code, _label, message) => {
      const create = repositoryOver([failure(code, message)]);
      const update = repositoryOver([failure(code, message)]);

      const failures = await Promise.all([
        create.repository.create({ clientId: CLIENT, title: 'Loja', stages: null }).then(
          () => undefined,
          (error: unknown) => error as Error,
        ),
        update.repository.update(P1, { title: 'Novo' }).then(
          () => undefined,
          (error: unknown) => error as Error,
        ),
      ]);

      for (const failed of failures) {
        expect(failed).toBeInstanceOf(Error);
        expect(failed).not.toBeInstanceOf(ValidationError);
        expect(failed).not.toBeInstanceOf(ServiceUnavailableError);
        expect(failed?.cause).toEqual({ code, status: 400 });
        expect(JSON.stringify(failed?.cause)).not.toContain('Acme');
      }
    },
  );

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

describe('approve', () => {
  const stageRows = (current: 1 | 2) => [
    stageRowOf(
      S1,
      1,
      current === 1 ? 'in_progress' : 'completed',
      current === 1 ? [] : [approvalRow],
    ),
    stageRowOf(S2, 2, current === 1 ? 'pending' : 'in_progress'),
  ];

  it('AC-16: calls approve_current_stage with the process and the expected stage only, and reads the process back', async () => {
    const { repository, queries, remaining } = repositoryOver([
      answer({ ...writeRowOf(P1), version: 2 }),
      answer({ ...detailRowOf(P1, stageRows(2)), version: 2 }),
    ]);

    const result = await repository.approve(P1, S1);

    expect(queries[0]).toEqual([
      ['rpc', 'approve_current_stage', { p_process_id: P1, p_expected_stage_id: S1 }],
    ]);
    // the second read is the detail read, with the stages and their approvals
    expect(queries[1]?.[1]).toEqual(['select', DETAIL_SELECT]);
    expect(remaining()).toBe(0);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.version).toBe(2);
    expect(result.value.stages.map((stage) => stage.status)).toEqual(['completed', 'in_progress']);
    expect(result.value.stages[0]?.approval?.approvedBy).toEqual({
      id: CEO,
      displayName: 'CEO Um',
    });
  });

  it('the approver is not an argument: nothing but the two ids goes to the database', async () => {
    const { repository, queries } = repositoryOver([
      answer(writeRowOf(P1)),
      answer(detailRowOf(P1, stageRows(2))),
    ]);

    await repository.approve(P1, S1);

    const [, , args] = queries[0]?.[0] ?? [];
    expect(Object.keys(args as object).sort()).toEqual(['p_expected_stage_id', 'p_process_id']);
  });

  it.each([
    [
      'E-03: a completed or cancelled process',
      failure('P0001', 'PROCESS_NOT_ACTIVE'),
      ProcessNotActiveError,
      'PROCESS_NOT_ACTIVE',
    ],
    ['an unknown process', failure('P0001', 'NOT_FOUND'), NotFoundError, 'NOT_FOUND'],
    ['invalid input', failure('P0001', 'INVALID_INPUT'), ValidationError, 'VALIDATION_ERROR'],
    ['a denial', failure('42501', 'FORBIDDEN'), ForbiddenError, 'FORBIDDEN'],
  ])('maps %s to its domain error, with no second read', async (_label, outcome, type, code) => {
    const { repository, queries } = repositoryOver([outcome]);

    const result = await repository.approve(P1, S1);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(type);
    expect(result.error.code).toBe(code);
    expect(queries).toHaveLength(1);
  });

  it('a process that is not there names the process in the 404', async () => {
    const { repository } = repositoryOver([failure('P0001', 'NOT_FOUND')]);

    const result = await repository.approve(P1, S1);

    expect(!result.ok && result.error.detail).toBe('Process not found.');
  });

  it('a denial is logged as a bypass of layer 1 and carries no detail of the database', async () => {
    const { repository, warn } = repositoryOver([
      failure('42501', 'FORBIDDEN: Failing row contains (Processo Secreto)'),
    ]);

    const result = await repository.approve(P1, S1);

    expect(warn.warn).toHaveBeenCalledWith(
      { event: 'authz.database_denied', operation: 'approve_current_stage' },
      'authz.database_denied',
    );
    expect(JSON.stringify(!result.ok && result.error)).not.toContain('Secreto');
    expect(!result.ok && result.error.detail).toBe('Access denied.');
  });

  it('E-01, E-02: STALE_STAGE reads the process again and names the stage that is current now', async () => {
    const { repository, queries, remaining } = repositoryOver([
      failure('P0001', 'STALE_STAGE'),
      answer(detailRowOf(P1, stageRows(2))),
    ]);

    const result = await repository.approve(P1, S1);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(StaleStageError);
    expect(result.error.code).toBe('STALE_STAGE');
    expect(result.error.extensions).toEqual({ currentStageId: S2 });
    expect(queries).toHaveLength(2);
    expect(queries[1]?.[1]).toEqual(['select', DETAIL_SELECT]);
    expect(remaining()).toBe(0);
  });

  it('E-01: the cause of a stale stage is the code alone: nothing of the database error', async () => {
    const { repository } = repositoryOver([
      failure('P0001', 'STALE_STAGE'),
      answer(detailRowOf(P1, stageRows(2))),
    ]);

    const result = await repository.approve(P1, S1);

    expect(!result.ok && result.error.cause).toEqual({ code: 'P0001' });
  });

  it('a stale stage on a process that is no longer active (a cancel landed in between) has no current stage', async () => {
    const cancelled = {
      ...detailRowOf(P1, stageRows(2)),
      status: 'cancelled',
      cancelled_at: AT,
    };
    const { repository } = repositoryOver([failure('P0001', 'STALE_STAGE'), answer(cancelled)]);

    const result = await repository.approve(P1, S1);

    expect(!result.ok && result.error.extensions).toEqual({ currentStageId: null });
  });

  it('a stale stage on a process that cannot be read any more is a 404', async () => {
    const { repository } = repositoryOver([failure('P0001', 'STALE_STAGE'), answer(null)]);

    const result = await repository.approve(P1, S1);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(NotFoundError);
  });

  it('E-21: the re-read after a stale stage that cannot reach the database is a 503', async () => {
    const { repository } = repositoryOver([
      failure('P0001', 'STALE_STAGE'),
      failure('', 'fetch failed', 0),
    ]);

    await expect(repository.approve(P1, S1)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('E-21: a rolled back transaction (deadlock, serialization failure) and an unreachable database are a 503', async () => {
    for (const outcome of [
      failure('40P01', 'deadlock detected', 500),
      failure('40001', 'could not serialize access', 500),
      failure('', 'fetch failed', 0),
    ]) {
      const { repository } = repositoryOver([outcome]);
      await expect(repository.approve(P1, S1)).rejects.toBeInstanceOf(ServiceUnavailableError);
    }
  });

  it('a 503 from a rolled back transaction carries the SQLSTATE and the status, never the message', async () => {
    const { repository } = repositoryOver([
      failure('40P01', 'deadlock detected: process 1 waits on Processo Secreto', 500),
    ]);

    const error = await repository.approve(P1, S1).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ServiceUnavailableError);
    expect((error as Error).cause).toEqual({ code: '40P01', status: 500 });
    expect(JSON.stringify((error as Error).cause)).not.toContain('Secreto');
  });

  it('an unmapped error (a CHECK violation too) is an unexpected error (500), with only code and status as cause', async () => {
    const { repository } = repositoryOver([
      failure(
        '23514',
        'new row violates check constraint: Failing row contains (Processo Secreto)',
      ),
    ]);

    const error = await repository.approve(P1, S1).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(ServiceUnavailableError);
    expect((error as Error).cause).toEqual({ code: '23514', status: 400 });
    expect(JSON.stringify((error as Error).cause)).not.toContain('Secreto');
  });

  it('F-105: INVARIANT_VIOLATION (the function checked its own writes and found the state broken) is an unexpected error (500), not a 400, not a 503, with only the SQLSTATE and the status as cause', async () => {
    const { repository, queries } = repositoryOver([failure('P0001', 'INVARIANT_VIOLATION')]);

    const error = await repository.approve(P1, S1).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(ServiceUnavailableError);
    expect(error).not.toBeInstanceOf(ValidationError);
    expect((error as Error).message).toBe('approve_current_stage failed unexpectedly');
    expect((error as Error).cause).toEqual({ code: 'P0001', status: 400 });
    // no re-read, no second call: the answer is a 500, and nothing was written
    expect(queries).toHaveLength(1);
  });

  it('F-105: the code is not in the catalog, so a database message that carried a row would not reach the cause either', async () => {
    const { repository } = repositoryOver([
      failure('P0001', 'INVARIANT_VIOLATION: Failing row contains (Processo Secreto)'),
    ]);

    const error = await repository.approve(P1, S1).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(Error);
    expect(JSON.stringify((error as Error).cause)).not.toContain('Secreto');
  });

  it('E-21: an approval saved and then lost from sight (the session ended) is a 404, not a 500', async () => {
    const { repository } = repositoryOver([answer(writeRowOf(P1)), answer(null)]);

    const result = await repository.approve(P1, S1);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(NotFoundError);
  });

  it('E-21: an approval saved whose read back cannot reach the database is a 503', async () => {
    const { repository } = repositoryOver([answer(writeRowOf(P1)), failure('', 'fetch failed', 0)]);

    await expect(repository.approve(P1, S1)).rejects.toBeInstanceOf(ServiceUnavailableError);
  });

  it('F-81: a process that breaks an invariant after the approval is a 500 and is logged without any title', async () => {
    // two stages in progress after an approval (I2): only a defect or a hand-made row gets here
    const broken = detailRowOf(P1, [
      stageRowOf(S1, 1, 'in_progress'),
      stageRowOf(S2, 2, 'in_progress'),
    ]);
    const { repository, warn } = repositoryOver([answer(writeRowOf(P1)), answer(broken)]);

    await expect(repository.approve(P1, S1)).rejects.toThrow(
      'a process read from the database breaks its invariants',
    );
    expect(warn.error).toHaveBeenCalledWith(
      { event: 'tracking.process_invariant_violated', processId: P1, invariants: ['I2'] },
      'tracking.process_invariant_violated',
    );
  });
});

describe('listByClient', () => {
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
        currentStage: { id: S1, position: 2, name: 'Fase 1' },
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

  it('a completed process has no current stage', async () => {
    const { repository } = repositoryOver([
      answer([
        summaryRowOf(P1, FIRST, {
          total: 2,
          completed: 2,
          current: [],
          status: 'completed',
          completedAt: FIRST,
        }),
      ]),
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

describe('F-81: what is read must hold the invariants, not only the shape', () => {
  const SECRET_TITLE = 'Titulo Secreto Acme';
  const withTitle = (row: object) => ({ ...row, title: SECRET_TITLE });
  const approved = [approvalRow];

  /** Rows that Zod understands and I1 to I5 refuse, with the invariants each one breaks. */
  const BROKEN_DETAILS: [string, object, string[]][] = [
    [
      'an active process with no stage in progress (I2)',
      detailRowOf(P1, [stageRowOf(S1, 1, 'pending'), stageRowOf(S2, 2, 'pending')]),
      ['I2'],
    ],
    [
      'an active process with two stages in progress (I2)',
      detailRowOf(P1, [stageRowOf(S1, 1, 'in_progress'), stageRowOf(S2, 2, 'in_progress')]),
      ['I2'],
    ],
    [
      'a gap in the stage positions (I1)',
      detailRowOf(P1, [stageRowOf(S1, 1, 'in_progress'), stageRowOf(S2, 3, 'pending')]),
      ['I1'],
    ],
    [
      'a completed stage with no approval (I5)',
      detailRowOf(P1, [stageRowOf(S1, 1, 'completed'), stageRowOf(S2, 2, 'in_progress')]),
      ['I5'],
    ],
    [
      'a completed process that still has a stage to do (I3)',
      {
        ...detailRowOf(P1, [
          stageRowOf(S1, 1, 'completed', approved),
          stageRowOf(S2, 2, 'pending'),
        ]),
        status: 'completed',
        completed_at: AT,
      },
      ['I3'],
    ],
    [
      'a cancelled process whose stages are out of order (I4)',
      {
        ...detailRowOf(P1, [
          stageRowOf(S1, 1, 'pending'),
          stageRowOf(S2, 2, 'completed', approved),
        ]),
        status: 'cancelled',
        cancelled_at: AT,
      },
      ['I4'],
    ],
  ];

  it.each(BROKEN_DETAILS)(
    'find fails closed on %s, and the log names the process and the invariant only',
    async (_label, row, invariants) => {
      const { repository, warn } = repositoryOver([answer(withTitle(row))]);

      const failed = await repository.find(P1).then(
        () => undefined,
        (error: unknown) => error as Error,
      );

      expect(failed).toBeInstanceOf(Error);
      expect(failed).not.toBeInstanceOf(ServiceUnavailableError);
      expect(failed?.message).toMatch(/breaks its invariants/);
      expect(warn.error).toHaveBeenCalledTimes(1);
      expect(warn.error).toHaveBeenCalledWith(
        { event: 'tracking.process_invariant_violated', processId: P1, invariants },
        'tracking.process_invariant_violated',
      );
      const logged = JSON.stringify(warn.error.mock.calls);
      expect(logged).not.toContain('Secreto');
      expect(logged).not.toContain('Fase');
    },
  );

  it('a healthy process, of any status, logs nothing', async () => {
    const rows = [
      detailRowOf(P1, [stageRowOf(S1, 1, 'in_progress')]),
      {
        ...detailRowOf(P1, [stageRowOf(S1, 1, 'completed', approved)]),
        status: 'completed',
        completed_at: AT,
      },
      {
        ...detailRowOf(P1, [
          stageRowOf(S1, 1, 'completed', approved),
          stageRowOf(S2, 2, 'in_progress'),
        ]),
        status: 'cancelled',
        cancelled_at: AT,
      },
    ];
    for (const row of rows) {
      const { repository, warn } = repositoryOver([answer(row)]);

      expect(await repository.find(P1)).not.toBeNull();
      expect(warn.error).not.toHaveBeenCalled();
    }
  });

  it('the re-read after a write checks too: a process that breaks an invariant is 500 and is logged', async () => {
    const broken = detailRowOf(P1, [stageRowOf(S1, 1, 'pending')]);
    const create = repositoryOver([answer(writeRowOf(P1)), answer(broken)]);
    const update = repositoryOver([answer(writeRowOf(P1)), answer(broken)]);

    await expect(
      create.repository.create({ clientId: CLIENT, title: 'Loja', stages: null }),
    ).rejects.toThrow(/breaks its invariants/);
    await expect(update.repository.update(P1, { title: 'Novo' })).rejects.toThrow(
      /breaks its invariants/,
    );
    expect(create.warn.error).toHaveBeenCalledTimes(1);
    expect(update.warn.error).toHaveBeenCalledTimes(1);
  });

  it.each([
    [
      'an active process whose progress does not add up (I2)',
      summaryRowOf(P1, FIRST, {
        total: 3,
        completed: 2,
        current: [{ id: S1, position: 1, name: 'Fase 1' }],
      }),
      ['I2'],
    ],
    [
      'an active process with no current stage (I2)',
      summaryRowOf(P1, FIRST, { total: 3, completed: 0, current: [] }),
      ['I2'],
    ],
    [
      'a completed process with a stage left (I3)',
      summaryRowOf(P1, FIRST, {
        total: 3,
        completed: 2,
        current: [],
        status: 'completed',
        completedAt: FIRST,
      }),
      ['I3'],
    ],
    [
      'a cancelled process with no date (I4)',
      summaryRowOf(P1, FIRST, { total: 3, completed: 1, status: 'cancelled' }),
      ['I4'],
    ],
  ])('the list fails closed on %s', async (_label, row, invariants) => {
    const { repository, warn } = repositoryOver([answer([withTitle(row)])]);

    await expect(repository.listByClient(CLIENT, { limit: 5 })).rejects.toThrow(
      /breaks its invariants/,
    );
    expect(warn.error).toHaveBeenCalledWith(
      { event: 'tracking.process_invariant_violated', processId: P1, invariants },
      'tracking.process_invariant_violated',
    );
    expect(JSON.stringify(warn.error.mock.calls)).not.toContain('Secreto');
  });

  it('one broken process fails the whole page of its client: the healthy ones are not shown either', async () => {
    const { repository, warn } = repositoryOver([
      answer([
        summaryRowOf(P1, FIRST, { total: 3, completed: 1 }),
        summaryRowOf(P2, SECOND, { total: 3, completed: 2, current: [] }),
      ]),
    ]);

    await expect(repository.listByClient(CLIENT, { limit: 5 })).rejects.toThrow(
      /breaks its invariants/,
    );
    expect(warn.error).toHaveBeenCalledTimes(1);
    expect(warn.error).toHaveBeenCalledWith(
      expect.objectContaining({ processId: P2, invariants: ['I2'] }),
      'tracking.process_invariant_violated',
    );
  });

  it('a healthy page logs nothing', async () => {
    const { repository, warn } = repositoryOver([
      answer([
        summaryRowOf(P1, FIRST, { total: 3, completed: 1 }),
        summaryRowOf(P2, SECOND, {
          total: 2,
          completed: 2,
          current: [],
          status: 'completed',
          completedAt: SECOND,
        }),
      ]),
    ]);

    const page = await repository.listByClient(CLIENT, { limit: 5 });

    expect(page?.items).toHaveLength(2);
    expect(warn.error).not.toHaveBeenCalled();
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
