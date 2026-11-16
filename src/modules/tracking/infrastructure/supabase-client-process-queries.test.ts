import type { SupabaseClient } from '@supabase/supabase-js';
import { describe, expect, it, vi } from 'vitest';
import type { Database } from '@/shared/db/database.types';
import { ServiceUnavailableError, ValidationError } from '@/shared/kernel';
import { createSupabaseClientProcessQueries } from './supabase-client-process-queries';

const TENANT = '00000000-0000-4000-8000-00000000000a';
const OTHER_TENANT = '00000000-0000-4000-8000-00000000000b';
const P1 = '00000000-0000-4000-8000-0000000001a1';
const P2 = '00000000-0000-4000-8000-0000000001a2';
const P3 = '00000000-0000-4000-8000-0000000001a3';

const PROCESS_COLUMNS =
  'id, client_id, title, status, created_at, updated_at, completed_at, cancelled_at';
const DETAIL_SELECT =
  `${PROCESS_COLUMNS}, ` +
  'stages:process_stages(position, name, description, status, started_at, completed_at)';
const SUMMARY_SELECT =
  `${PROCESS_COLUMNS}, total_stages:process_stages(count), ` +
  'completed_stages:process_stages(count), current_stage:process_stages(position, name)';

type Outcome = { data: unknown; error: unknown; status: number };

const answer = (data: unknown, status = 200): Outcome => ({ data, error: null, status });
const failure = (code: string, message: string, status = 400): Outcome => ({
  data: null,
  error: { code, message },
  status,
});

const AT = '2026-11-16T11:30:24.984084+00:00';
const FIRST = '2026-11-16T11:00:00.000003+00:00';
const SECOND = '2026-11-16T10:00:00.000002+00:00';
const THIRD = '2026-11-16T09:00:00.000001+00:00';

const stageRowOf = (
  position: number,
  status: 'pending' | 'in_progress' | 'completed',
  description: string | null = null,
) => ({
  position,
  name: `Fase ${position}`,
  description,
  status,
  started_at: status === 'pending' ? null : AT,
  completed_at: status === 'completed' ? AT : null,
});

/** A process row as the detail read returns it, with its stages. */
const detailRowOf = (id: string, stages: unknown[], extra: Record<string, unknown> = {}) => ({
  id,
  client_id: TENANT,
  title: 'Processo',
  status: 'active',
  created_at: AT,
  updated_at: AT,
  completed_at: null,
  cancelled_at: null,
  stages,
  ...extra,
});

const summaryRowOf = (
  id: string,
  createdAt: string,
  extra: {
    clientId?: string;
    total?: number;
    completed?: number;
    current?: unknown[];
    status?: string;
    completedAt?: string | null;
    cancelledAt?: string | null;
  } = {},
) => ({
  id,
  client_id: extra.clientId ?? TENANT,
  title: `Processo ${id.slice(-1)}`,
  status: extra.status ?? 'active',
  created_at: createdAt,
  updated_at: createdAt,
  completed_at: extra.completedAt ?? null,
  cancelled_at: extra.cancelledAt ?? null,
  total_stages: [{ count: extra.total ?? 3 }],
  completed_stages: [{ count: extra.completed ?? 0 }],
  // a healthy active process: the stage after the completed ones is the current one
  current_stage: extra.current ?? [{ position: (extra.completed ?? 0) + 1, name: 'Fase 1' }],
});

/**
 * Records every call of a query chain and answers the scripted outcomes in order, one per awaited
 * query. Any method of the chain is accepted: what matters is what was called.
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
    rpc: () => {
      throw new Error('the client panel never calls a function: it only reads');
    },
  } as unknown as SupabaseClient<Database>;
  return { supabase, recorded: queries, remaining: () => queue.length };
}

const queriesOver = (outcomes: Outcome[]) => {
  const logger = { error: vi.fn(), warn: vi.fn() };
  const fake = fakeSupabase(outcomes);
  return {
    queries: createSupabaseClientProcessQueries(fake.supabase, { logger }),
    logger,
    recorded: fake.recorded,
    remaining: fake.remaining,
  };
};

describe('find', () => {
  it('AC-20: reads the detail in one request, explicit columns, filtered by id and by the tenant, stages in order', async () => {
    const { queries, recorded } = queriesOver([
      answer(
        detailRowOf(P1, [
          stageRowOf(2, 'in_progress'),
          stageRowOf(1, 'completed', 'Detalhe'),
          stageRowOf(3, 'pending'),
        ]),
      ),
    ]);

    const process = await queries.find(TENANT, P1);

    expect(recorded).toEqual([
      [
        ['from', 'processes'],
        ['select', DETAIL_SELECT],
        ['eq', 'id', P1],
        ['eq', 'client_id', TENANT],
        ['order', 'position', { referencedTable: 'stages', ascending: true }],
        ['retry', false],
        ['maybeSingle'],
      ],
    ]);
    expect(process).toEqual({
      id: P1,
      title: 'Processo',
      status: 'active',
      currentStage: { position: 2, name: 'Fase 2' },
      totalStages: 3,
      completedStages: 1,
      createdAt: new Date('2026-11-16T11:30:24.984Z'),
      updatedAt: new Date('2026-11-16T11:30:24.984Z'),
      completedAt: null,
      stages: [
        {
          position: 1,
          name: 'Fase 1',
          description: 'Detalhe',
          status: 'completed',
          startedAt: new Date('2026-11-16T11:30:24.984Z'),
          completedAt: new Date('2026-11-16T11:30:24.984Z'),
        },
        {
          position: 2,
          name: 'Fase 2',
          description: null,
          status: 'in_progress',
          startedAt: new Date('2026-11-16T11:30:24.984Z'),
          completedAt: null,
        },
        {
          position: 3,
          name: 'Fase 3',
          description: null,
          status: 'pending',
          startedAt: null,
          completedAt: null,
        },
      ],
    });
  });

  it('AC-20: the read model has no version, client id, stage id or approval, even if the row carried them', async () => {
    const { queries } = queriesOver([
      answer(
        detailRowOf(
          P1,
          [{ ...stageRowOf(1, 'in_progress'), id: P2, approval: [{ approved_by: 'x' }] }],
          {
            version: 7,
            approved_by: '11111111-1111-4111-8111-111111111111',
          },
        ),
      ),
    ]);

    const process = await queries.find(TENANT, P1);

    const json = JSON.stringify(process);
    for (const internal of [
      'version',
      'client_id',
      'clientId',
      'approval',
      'approved',
      '"id":"' + P2,
    ]) {
      expect(json).not.toContain(internal);
    }
    expect(Object.keys(process ?? {}).sort()).toEqual(
      [
        'completedAt',
        'completedStages',
        'createdAt',
        'currentStage',
        'id',
        'stages',
        'status',
        'title',
        'totalStages',
        'updatedAt',
      ].sort(),
    );
  });

  it('E-05: is null when the process is not found (another tenant filtered by the query, or no such id)', async () => {
    const { queries } = queriesOver([answer(null)]);

    expect(await queries.find(TENANT, P1)).toBeNull();
  });

  it('a completed process has no current stage, and a cancelled one keeps where it stopped', async () => {
    const completed = queriesOver([
      answer(
        detailRowOf(P1, [stageRowOf(1, 'completed'), stageRowOf(2, 'completed')], {
          status: 'completed',
          completed_at: AT,
        }),
      ),
    ]);
    const cancelled = queriesOver([
      answer(
        detailRowOf(P2, [stageRowOf(1, 'completed'), stageRowOf(2, 'in_progress')], {
          status: 'cancelled',
          cancelled_at: AT,
        }),
      ),
    ]);

    expect(await completed.queries.find(TENANT, P1)).toMatchObject({
      status: 'completed',
      currentStage: null,
      completedStages: 2,
      totalStages: 2,
    });
    expect(await cancelled.queries.find(TENANT, P2)).toMatchObject({
      status: 'cancelled',
      currentStage: { position: 2 },
      completedAt: null,
    });
  });

  it('AC-09: a row that is not the tenant is a defect: 500, nothing mapped, only the process id logged', async () => {
    const { queries, logger } = queriesOver([
      answer(detailRowOf(P1, [stageRowOf(1, 'in_progress')], { client_id: OTHER_TENANT })),
    ]);

    await expect(queries.find(TENANT, P1)).rejects.toThrow('not the tenant of the session');

    expect(logger.error).toHaveBeenCalledTimes(1);
    expect(logger.error).toHaveBeenCalledWith(
      { event: 'tracking.client_panel_tenant_mismatch', processId: P1 },
      'tracking.client_panel_tenant_mismatch',
    );
    expect(JSON.stringify(logger.error.mock.calls)).not.toContain(OTHER_TENANT);
    expect(JSON.stringify(logger.error.mock.calls)).not.toContain(TENANT);
  });

  it('F-81: a process with no stage is not understood: 500, never an empty detail', async () => {
    const { queries } = queriesOver([answer(detailRowOf(P1, []))]);

    await expect(queries.find(TENANT, P1)).rejects.toThrow('not understood');
  });

  it.each([
    ['an unknown status', { status: 'archived' }],
    ['a created_at that is not a timestamp', { created_at: 'yesterday' }],
    ['a title that is not text', { title: 42 }],
    ['an id that is not a uuid', { id: 'nope' }],
  ])('a row with %s is not understood: 500', async (_label, change) => {
    const { queries } = queriesOver([
      answer(detailRowOf(P1, [stageRowOf(1, 'in_progress')], change)),
    ]);

    await expect(queries.find(TENANT, P1)).rejects.toThrow('not understood');
  });

  it('F-81: stages out of order, or an active process with no stage in progress, fail closed with the invariants named', async () => {
    const outOfOrder = queriesOver([
      answer(detailRowOf(P1, [stageRowOf(1, 'pending'), stageRowOf(2, 'in_progress')])),
    ]);
    const noCurrent = queriesOver([
      answer(detailRowOf(P2, [stageRowOf(1, 'completed'), stageRowOf(2, 'pending')])),
    ]);

    await expect(outOfOrder.queries.find(TENANT, P1)).rejects.toThrow('breaks its invariants');
    await expect(noCurrent.queries.find(TENANT, P2)).rejects.toThrow('breaks its invariants');

    expect(outOfOrder.logger.error).toHaveBeenCalledWith(
      {
        event: 'tracking.process_invariant_violated',
        panel: 'client',
        processId: P1,
        invariants: ['I2'],
      },
      'tracking.process_invariant_violated',
    );
    // what is logged has no title and no stage name (SEC-16)
    expect(JSON.stringify(outOfOrder.logger.error.mock.calls)).not.toContain('Processo');
    expect(JSON.stringify(outOfOrder.logger.error.mock.calls)).not.toContain('Fase');
  });

  it('F-81: a completed process with a stage that is not completed, and a missing date, fail closed', async () => {
    const half = queriesOver([
      answer(
        detailRowOf(P1, [stageRowOf(1, 'completed'), stageRowOf(2, 'in_progress')], {
          status: 'completed',
          completed_at: AT,
        }),
      ),
    ]);

    await expect(half.queries.find(TENANT, P1)).rejects.toThrow('breaks its invariants');
  });

  it('E-21: a slow or dead database is a ServiceUnavailableError, with only the SQLSTATE and the status as cause', async () => {
    const { queries } = queriesOver([
      {
        data: null,
        error: { code: 'PGRST000', message: 'Failing row (Processo secreto)' },
        status: 503,
      },
    ]);

    const error = await queries.find(TENANT, P1).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ServiceUnavailableError);
    expect((error as Error).cause).toEqual({ code: 'PGRST000', status: 503 });
    expect(JSON.stringify((error as Error).cause)).not.toContain('secreto');
  });

  it('an unexpected database error is a plain error (500), without the message of the database in the cause', async () => {
    const { queries } = queriesOver([
      failure('XX000', 'Failing row contains (Processo secreto)', 400),
    ]);

    const error = await queries.find(TENANT, P1).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(ServiceUnavailableError);
    expect((error as Error).cause).toEqual({ code: 'XX000', status: 400 });
  });

  it.each(['40P01', '40001'])(
    'a read that Postgres rolled back (%s) is 503, whatever the HTTP status, with the SQLSTATE and the status as cause',
    async (code) => {
      for (const status of [400, 500]) {
        const { queries } = queriesOver([failure(code, 'Failing row (Processo secreto)', status)]);

        const error = await queries.find(TENANT, P1).catch((caught: unknown) => caught);

        expect(error).toBeInstanceOf(ServiceUnavailableError);
        expect((error as Error).cause).toEqual({ code, status });
        expect(JSON.stringify((error as Error).cause)).not.toContain('secreto');
      }
    },
  );

  it('F-98: a row of another tenant that is ALSO malformed still raises the tenant alarm, not "not understood"', async () => {
    const { queries, logger } = queriesOver([
      answer(
        detailRowOf(P1, [stageRowOf(1, 'in_progress')], {
          client_id: OTHER_TENANT,
          status: 'archived',
          created_at: 'yesterday',
          title: 42,
        }),
      ),
    ]);

    await expect(queries.find(TENANT, P1)).rejects.toThrow('not the tenant of the session');

    expect(logger.error).toHaveBeenCalledWith(
      { event: 'tracking.client_panel_tenant_mismatch', processId: P1 },
      'tracking.client_panel_tenant_mismatch',
    );
  });

  it('a row with no readable id or client id is not understood, and raises no tenant alarm', async () => {
    const noClient = queriesOver([
      answer({ ...detailRowOf(P1, [stageRowOf(1, 'in_progress')]), client_id: null }),
    ]);
    const noId = queriesOver([
      answer({ ...detailRowOf(P1, [stageRowOf(1, 'in_progress')]), id: 'nope' }),
    ]);

    await expect(noClient.queries.find(TENANT, P1)).rejects.toThrow('not understood');
    await expect(noId.queries.find(TENANT, P1)).rejects.toThrow('not understood');
    expect(noClient.logger.error).not.toHaveBeenCalled();
    expect(noId.logger.error).not.toHaveBeenCalled();
  });
});

describe('list', () => {
  it('AC-20: reads the first page with explicit columns, filtered by the tenant, newest first, one row more than asked', async () => {
    const { queries, recorded } = queriesOver([
      answer([summaryRowOf(P1, FIRST), summaryRowOf(P2, SECOND), summaryRowOf(P3, THIRD)]),
    ]);

    const page = await queries.list(TENANT, { limit: 2 });

    expect(recorded).toEqual([
      [
        ['from', 'processes'],
        ['select', SUMMARY_SELECT],
        ['eq', 'client_id', TENANT],
        ['eq', 'completed_stages.status', 'completed'],
        ['eq', 'current_stage.status', 'in_progress'],
        ['retry', false],
        ['order', 'created_at', { ascending: false }],
        ['order', 'id', { ascending: true }],
        ['limit', 3],
      ],
    ]);
    expect(page.items.map((item) => item.id)).toEqual([P1, P2]);
    expect(page.next).toEqual({ createdAt: SECOND, id: P2 });
    expect(page.items[0]).toEqual({
      id: P1,
      title: 'Processo 1',
      status: 'active',
      currentStage: { position: 1, name: 'Fase 1' },
      totalStages: 3,
      completedStages: 0,
      createdAt: new Date('2026-11-16T11:00:00.000Z'),
      updatedAt: new Date('2026-11-16T11:00:00.000Z'),
      completedAt: null,
    });
  });

  it('AC-20: the last page has no next position, and an empty one is just empty', async () => {
    const last = queriesOver([answer([summaryRowOf(P1, FIRST)])]);
    const empty = queriesOver([answer([])]);

    expect(await last.queries.list(TENANT, { limit: 2 })).toMatchObject({ next: null });
    expect(await empty.queries.list(TENANT, { limit: 2 })).toEqual({ items: [], next: null });
  });

  it('pages after a position with two queries: the same instant first, then the older rows', async () => {
    const { queries, recorded } = queriesOver([
      answer([summaryRowOf(P2, SECOND)]),
      answer([summaryRowOf(P3, THIRD)]),
    ]);

    const page = await queries.list(TENANT, { limit: 5, after: { createdAt: SECOND, id: P1 } });

    expect(recorded.map((calls) => calls.map(([method]) => method))).toEqual([
      ['from', 'select', 'eq', 'eq', 'eq', 'retry', 'eq', 'gt', 'order', 'limit'],
      ['from', 'select', 'eq', 'eq', 'eq', 'retry', 'order', 'order', 'limit', 'lt'],
    ]);
    expect(recorded[0]).toContainEqual(['eq', 'created_at', SECOND]);
    expect(recorded[0]).toContainEqual(['gt', 'id', P1]);
    expect(recorded[0]).toContainEqual(['eq', 'client_id', TENANT]);
    expect(recorded[1]).toContainEqual(['lt', 'created_at', SECOND]);
    expect(recorded[1]).toContainEqual(['eq', 'client_id', TENANT]);
    expect(recorded[1]).toContainEqual(['limit', 5]);
    expect(page.items.map((item) => item.id)).toEqual([P2, P3]);
  });

  it('does not run the second query when the first one filled the page', async () => {
    const { queries, remaining } = queriesOver([
      answer([summaryRowOf(P2, SECOND), summaryRowOf(P3, SECOND)]),
    ]);

    const page = await queries.list(TENANT, { limit: 1, after: { createdAt: SECOND, id: P1 } });

    expect(remaining()).toBe(0);
    expect(page.items.map((item) => item.id)).toEqual([P2]);
    expect(page.next).toEqual({ createdAt: SECOND, id: P2 });
  });

  it('AC-09: one row of another tenant in a page is a defect: 500, nothing returned, only the process id logged', async () => {
    const { queries, logger } = queriesOver([
      answer([summaryRowOf(P1, FIRST), summaryRowOf(P2, SECOND, { clientId: OTHER_TENANT })]),
    ]);

    await expect(queries.list(TENANT, { limit: 5 })).rejects.toThrow(
      'not the tenant of the session',
    );

    expect(logger.error).toHaveBeenCalledWith(
      { event: 'tracking.client_panel_tenant_mismatch', processId: P2 },
      'tracking.client_panel_tenant_mismatch',
    );
    expect(JSON.stringify(logger.error.mock.calls)).not.toContain(OTHER_TENANT);
  });

  it('AC-09: the extra row that only tells there is another page is checked too', async () => {
    const { queries } = queriesOver([
      answer([summaryRowOf(P1, FIRST), summaryRowOf(P2, SECOND, { clientId: OTHER_TENANT })]),
    ]);

    await expect(queries.list(TENANT, { limit: 1 })).rejects.toThrow(
      'not the tenant of the session',
    );
  });

  it('F-81: a process with no stage in the list (a count of 0) is not understood: 500', async () => {
    const { queries } = queriesOver([
      answer([{ ...summaryRowOf(P1, FIRST), total_stages: [{ count: 0 }] }]),
    ]);

    await expect(queries.list(TENANT, { limit: 5 })).rejects.toThrow('not understood');
  });

  it('F-81: progress that does not add up, or a state without its date, fails the whole page', async () => {
    const wrongProgress = queriesOver([
      answer([
        summaryRowOf(P1, FIRST),
        summaryRowOf(P2, SECOND, { completed: 2, current: [{ position: 1, name: 'x' }] }),
      ]),
    ]);
    const noDate = queriesOver([
      answer([summaryRowOf(P1, FIRST, { status: 'completed', completed: 3, current: [] })]),
    ]);

    await expect(wrongProgress.queries.list(TENANT, { limit: 5 })).rejects.toThrow(
      'breaks its invariants',
    );
    await expect(noDate.queries.list(TENANT, { limit: 5 })).rejects.toThrow(
      'breaks its invariants',
    );
    expect(noDate.logger.error).toHaveBeenCalledWith(
      {
        event: 'tracking.process_invariant_violated',
        panel: 'client',
        processId: P1,
        invariants: ['I3'],
      },
      'tracking.process_invariant_violated',
    );
  });

  it('a completed and a cancelled row map as the panel shows them', async () => {
    const { queries } = queriesOver([
      answer([
        summaryRowOf(P1, FIRST, {
          status: 'completed',
          completed: 3,
          current: [],
          completedAt: AT,
        }),
        summaryRowOf(P2, SECOND, { status: 'cancelled', completed: 1, cancelledAt: AT }),
      ]),
    ]);

    const page = await queries.list(TENANT, { limit: 5 });

    expect(page.items[0]).toMatchObject({
      status: 'completed',
      currentStage: null,
      completedAt: new Date('2026-11-16T11:30:24.984Z'),
    });
    expect(page.items[1]).toMatchObject({
      status: 'cancelled',
      currentStage: { position: 2 },
      completedAt: null,
    });
    expect(JSON.stringify(page)).not.toContain('cancelled_at');
    expect(JSON.stringify(page)).not.toContain('cancelledAt');
  });

  it('F-53: a position the database cannot read is a 400 on the cursor, with only the SQLSTATE as cause', async () => {
    const { queries } = queriesOver([
      failure('22008', 'date/time field value out of range: "2026-01-01T00:00:00+15:59"'),
    ]);

    const error = await queries
      .list(TENANT, { limit: 5, after: { createdAt: SECOND, id: P1 } })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ValidationError);
    expect((error as ValidationError).issues).toEqual([
      { path: 'query.cursor', message: 'Invalid cursor' },
    ]);
    expect((error as Error).cause).toEqual({ code: '22008' });
  });

  it('F-98: a position the database refused is logged as a warning with the SQLSTATE only, so a drift of the bounds is seen', async () => {
    const { queries, logger } = queriesOver([
      failure('22008', 'date/time field value out of range: "2026-01-01T00:00:00+15:59"'),
    ]);

    await queries
      .list(TENANT, { limit: 5, after: { createdAt: SECOND, id: P1 } })
      .catch((caught: unknown) => caught);

    expect(logger.warn.mock.calls).toEqual([
      [
        { event: 'tracking.client_panel_cursor_refused', code: '22008' },
        'tracking.client_panel_cursor_refused',
      ],
    ]);
    expect(JSON.stringify(logger.warn.mock.calls)).not.toContain('2026');
  });

  it('a class 22 error with no position given is not the caller fault: 500', async () => {
    const { queries } = queriesOver([failure('22008', 'out of range')]);

    const error = await queries.list(TENANT, { limit: 5 }).catch((caught: unknown) => caught);

    expect(error).not.toBeInstanceOf(ValidationError);
    expect(error).toBeInstanceOf(Error);
  });

  it('a class 22 error with no position given logs no cursor warning', async () => {
    const { queries, logger } = queriesOver([failure('22008', 'out of range')]);

    await queries.list(TENANT, { limit: 5 }).catch((caught: unknown) => caught);

    expect(logger.warn).not.toHaveBeenCalled();
  });

  it.each(['40P01', '40001'])(
    'a read that Postgres rolled back (%s) is 503 on the first query and on the second, with the SQLSTATE and the status as cause',
    async (code) => {
      const first = queriesOver([failure(code, 'Failing row (Processo secreto)', 500)]);
      const second = queriesOver([
        answer([]),
        failure(code, 'Failing row (Processo secreto)', 400),
      ]);

      const firstError = await first.queries
        .list(TENANT, { limit: 5 })
        .catch((caught: unknown) => caught);
      const secondError = await second.queries
        .list(TENANT, { limit: 5, after: { createdAt: SECOND, id: P1 } })
        .catch((caught: unknown) => caught);

      expect(firstError).toBeInstanceOf(ServiceUnavailableError);
      expect((firstError as Error).cause).toEqual({ code, status: 500 });
      expect(secondError).toBeInstanceOf(ServiceUnavailableError);
      expect((secondError as Error).cause).toEqual({ code, status: 400 });
    },
  );

  it('F-98: a row of another tenant that is ALSO malformed still raises the tenant alarm, in the first query and in the second', async () => {
    const foreignAndBroken = {
      ...summaryRowOf(P2, SECOND, { clientId: OTHER_TENANT }),
      total_stages: [],
    };
    const first = queriesOver([answer([summaryRowOf(P1, FIRST), foreignAndBroken])]);
    const second = queriesOver([answer([]), answer([foreignAndBroken])]);

    await expect(first.queries.list(TENANT, { limit: 5 })).rejects.toThrow(
      'not the tenant of the session',
    );
    await expect(
      second.queries.list(TENANT, { limit: 5, after: { createdAt: SECOND, id: P1 } }),
    ).rejects.toThrow('not the tenant of the session');

    for (const { logger } of [first, second]) {
      expect(logger.error).toHaveBeenCalledWith(
        { event: 'tracking.client_panel_tenant_mismatch', processId: P2 },
        'tracking.client_panel_tenant_mismatch',
      );
    }
  });

  it('F-81: the invariants are checked on the lookahead row too: a corrupt process fails the page that points at it', async () => {
    const corrupt = summaryRowOf(P2, SECOND, {
      completed: 2,
      current: [{ position: 1, name: 'x' }],
    });
    const { queries, logger } = queriesOver([answer([summaryRowOf(P1, FIRST), corrupt])]);

    // limit 1: P1 is the page, P2 is only the row that tells there is a next page
    await expect(queries.list(TENANT, { limit: 1 })).rejects.toThrow('breaks its invariants');

    expect(logger.error).toHaveBeenCalledWith(
      {
        event: 'tracking.process_invariant_violated',
        panel: 'client',
        processId: P2,
        invariants: ['I2'],
      },
      'tracking.process_invariant_violated',
    );
  });

  it('E-21: a slow or dead database is a ServiceUnavailableError', async () => {
    const { queries } = queriesOver([failure('PGRST000', 'upstream timeout', 503)]);

    await expect(queries.list(TENANT, { limit: 5 })).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });
});
