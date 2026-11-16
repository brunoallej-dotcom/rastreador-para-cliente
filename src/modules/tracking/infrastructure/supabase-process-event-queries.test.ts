import type { SupabaseClient } from '@supabase/supabase-js';
import { describe, expect, it } from 'vitest';
import type { Database } from '@/shared/db/database.types';
import { ServiceUnavailableError, ValidationError } from '@/shared/kernel';
import { createSupabaseProcessEventQueries } from './supabase-process-event-queries';

const P1 = '00000000-0000-4000-8000-0000000001a1';
const S1 = '00000000-0000-4000-8000-000000000201';
const S2 = '00000000-0000-4000-8000-000000000202';
const CEO_ONE = '11111111-1111-4111-8111-111111111111';
const CEO_TWO = '11111111-1111-4111-8111-222222222222';

const EVENT_COLUMNS = 'id, occurred_at, actor_id, action, resource_id';
const ACTIONS = [
  'process.created',
  'process.updated',
  'process.cancelled',
  'process.completed',
  'stage.approved',
];

type Outcome = { data: unknown; error: unknown; status: number };

const answer = (data: unknown, status = 200): Outcome => ({ data, error: null, status });
const failure = (code: string, message: string, status = 400): Outcome => ({
  data: null,
  error: { code, message },
  status,
});

const eventRow = (id: number | string, action: string, actor: string | null, resource = P1) => ({
  id,
  occurred_at: '2026-11-16T12:00:00.123456+00:00',
  actor_id: actor,
  action,
  resource_id: resource,
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
  } as unknown as SupabaseClient<Database>;
  return { supabase, queries, remaining: () => queue.length };
}

const queriesOver = (outcomes: Outcome[]) => {
  const fake = fakeSupabase(outcomes);
  return { events: createSupabaseProcessEventQueries(fake.supabase), ...fake };
};

const PROCESS_FOUND = answer({ id: P1 });

describe('list', () => {
  it('AC-28: reads the process, then the events in id order with explicit columns, then the stages and the actors', async () => {
    const { events, queries, remaining } = queriesOver([
      PROCESS_FOUND,
      answer([
        eventRow(10, 'process.created', CEO_ONE),
        eventRow(11, 'stage.approved', CEO_TWO, S1),
        eventRow(12, 'process.updated', CEO_ONE),
      ]),
      answer([{ id: S1, position: 1, name: 'Briefing' }]),
      answer([
        { id: CEO_ONE, display_name: 'CEO Um' },
        { id: CEO_TWO, display_name: 'CEO Dois' },
      ]),
    ]);

    const page = await events.list(P1, { limit: 50 });

    expect(queries[0]).toEqual([
      ['from', 'processes'],
      ['select', 'id'],
      ['eq', 'id', P1],
      ['retry', false],
      ['maybeSingle'],
    ]);
    expect(queries[1]).toEqual([
      ['from', 'audit_events'],
      ['select', EVENT_COLUMNS],
      ['eq', 'process_id', P1],
      ['in', 'action', ACTIONS],
      ['order', 'id', { ascending: true }],
      ['limit', 51],
      ['retry', false],
    ]);
    expect(queries[2]).toEqual([
      ['from', 'process_stages'],
      ['select', 'id, position, name'],
      ['eq', 'process_id', P1],
      ['in', 'id', [S1]],
      ['retry', false],
    ]);
    expect(queries[3]).toEqual([
      ['from', 'profiles'],
      ['select', 'id, display_name'],
      ['in', 'id', [CEO_ONE, CEO_TWO]],
      ['retry', false],
    ]);
    expect(remaining()).toBe(0);
    expect(page).toEqual({
      items: [
        {
          id: '10',
          occurredAt: new Date('2026-11-16T12:00:00.123Z'),
          action: 'process.created',
          actor: { id: CEO_ONE, displayName: 'CEO Um' },
          details: {},
        },
        {
          id: '11',
          occurredAt: new Date('2026-11-16T12:00:00.123Z'),
          action: 'stage.approved',
          actor: { id: CEO_TWO, displayName: 'CEO Dois' },
          details: { stageId: S1, stagePosition: 1, stageName: 'Briefing' },
        },
        {
          id: '12',
          occurredAt: new Date('2026-11-16T12:00:00.123Z'),
          action: 'process.updated',
          actor: { id: CEO_ONE, displayName: 'CEO Um' },
          details: {},
        },
      ],
      next: null,
    });
  });

  it('SEC-16: a process.updated event has no title anywhere: not in the details, not in what is read', async () => {
    const { events, queries } = queriesOver([
      PROCESS_FOUND,
      answer([eventRow(1, 'process.updated', CEO_ONE)]),
      answer([{ id: CEO_ONE, display_name: 'CEO Um' }]),
    ]);

    const page = await events.list(P1, { limit: 50 });

    expect(page?.items[0]?.details).toEqual({});
    // no read of `processes.title` for the timeline: the process is read for its id only
    expect(queries[0]).toContainEqual(['select', 'id']);
    expect(JSON.stringify(queries)).not.toMatch(/title|metadata/);
  });

  it('the first page has no id filter; a later page resumes with a plain greater-than on the id', async () => {
    const first = queriesOver([PROCESS_FOUND, answer([])]);
    await first.events.list(P1, { limit: 2 });

    const later = queriesOver([PROCESS_FOUND, answer([])]);
    await later.events.list(P1, { limit: 2, after: { id: '9223372036854775807' } });

    expect(first.queries[1]?.map(([method]) => method)).not.toContain('gt');
    expect(later.queries[1]).toContainEqual(['gt', 'id', '9223372036854775807']);
    // the keyset is one query: the id is unique, so there is no tie to break and no `or` to build
    expect(later.queries[1]?.map(([method]) => method)).not.toContain('or');
  });

  it('asks for one row more than the page to know whether another page exists, and resumes after the last shown', async () => {
    const { events } = queriesOver([
      PROCESS_FOUND,
      answer([
        eventRow(5, 'process.created', null),
        eventRow(6, 'process.cancelled', null),
        eventRow(7, 'process.completed', null),
      ]),
    ]);

    const page = await events.list(P1, { limit: 2 });

    expect(page?.items.map((item) => item.id)).toEqual(['5', '6']);
    expect(page?.next).toEqual({ id: '6' });
  });

  it('a page that is exactly full has no next position', async () => {
    const { events } = queriesOver([
      PROCESS_FOUND,
      answer([eventRow(5, 'process.created', null), eventRow(6, 'process.cancelled', null)]),
    ]);

    const page = await events.list(P1, { limit: 2 });

    expect(page?.items).toHaveLength(2);
    expect(page?.next).toBeNull();
  });

  it('an event with no actor has a null actor and costs no profile read; a stage-less page costs no stage read', async () => {
    const { events, queries, remaining } = queriesOver([
      PROCESS_FOUND,
      answer([eventRow(1, 'process.created', null)]),
    ]);

    const page = await events.list(P1, { limit: 50 });

    expect(page?.items[0]?.actor).toBeNull();
    expect(queries.map((query) => query[0]?.[1])).toEqual(['processes', 'audit_events']);
    expect(remaining()).toBe(0);
  });

  it('looks each stage and each actor up once, however many events name them', async () => {
    const { events, queries } = queriesOver([
      PROCESS_FOUND,
      answer([
        eventRow(1, 'stage.approved', CEO_ONE, S1),
        eventRow(2, 'stage.approved', CEO_ONE, S2),
        eventRow(3, 'process.updated', CEO_ONE),
      ]),
      answer([
        { id: S1, position: 1, name: 'Um' },
        { id: S2, position: 2, name: 'Dois' },
      ]),
      answer([{ id: CEO_ONE, display_name: 'CEO Um' }]),
    ]);

    await events.list(P1, { limit: 50 });

    expect(queries[2]).toContainEqual(['in', 'id', [S1, S2]]);
    expect(queries[3]).toContainEqual(['in', 'id', [CEO_ONE]]);
  });

  it('an actor with no profile row is a null actor, and a stage with no row keeps the stage id alone', async () => {
    const { events } = queriesOver([
      PROCESS_FOUND,
      answer([eventRow(1, 'stage.approved', CEO_ONE, S1)]),
      answer([]),
      answer([]),
    ]);

    const page = await events.list(P1, { limit: 50 });

    expect(page?.items[0]).toMatchObject({ actor: null, details: { stageId: S1 } });
    expect(page?.items[0]?.details).toEqual({ stageId: S1 });
  });

  it('the id of a bigint comes as text, whether PostgREST sends a number or digits', async () => {
    const { events } = queriesOver([
      PROCESS_FOUND,
      answer([
        eventRow(41, 'process.created', null),
        eventRow('9007199254740993', 'process.completed', null),
      ]),
    ]);

    const page = await events.list(P1, { limit: 50 });

    expect(page?.items.map((item) => item.id)).toEqual(['41', '9007199254740993']);
  });

  it('a process that does not exist (or that the session cannot see) is null, with no event read', async () => {
    const { events, queries } = queriesOver([answer(null)]);

    expect(await events.list(P1, { limit: 50 })).toBeNull();
    expect(queries).toHaveLength(1);
  });

  it('an empty answer for a process that exists is an empty page', async () => {
    const { events } = queriesOver([PROCESS_FOUND, answer([])]);

    expect(await events.list(P1, { limit: 50 })).toEqual({ items: [], next: null });
  });

  it('fails closed on a row that is not understood: an action the timeline does not show, a bad id, a bad actor', async () => {
    const bad = [
      eventRow(1, 'client.updated', CEO_ONE),
      eventRow(0, 'process.created', CEO_ONE),
      eventRow(-3, 'process.created', CEO_ONE),
      eventRow(1.5, 'process.created', CEO_ONE),
      eventRow('abc', 'process.created', CEO_ONE),
      eventRow(1, 'process.created', 'not-a-uuid'),
      { ...eventRow(1, 'process.created', CEO_ONE), occurred_at: 'yesterday' },
      { id: 1, action: 'process.created' },
    ];
    for (const row of bad) {
      const { events } = queriesOver([PROCESS_FOUND, answer([row])]);
      await expect(events.list(P1, { limit: 50 })).rejects.toThrow(
        'the audit trail returned a row that is not understood',
      );
    }
  });

  it('fails closed on a stage or a profile row that is not understood', async () => {
    const stages = queriesOver([
      PROCESS_FOUND,
      answer([eventRow(1, 'stage.approved', null, S1)]),
      answer([{ id: S1, position: 0, name: 'Zero' }]),
    ]);
    await expect(stages.events.list(P1, { limit: 50 })).rejects.toThrow(
      'the stages table returned a row that is not understood',
    );

    const profiles = queriesOver([
      PROCESS_FOUND,
      answer([eventRow(1, 'process.created', CEO_ONE)]),
      answer([{ id: CEO_ONE }]),
    ]);
    await expect(profiles.events.list(P1, { limit: 50 })).rejects.toThrow(
      'the profiles table returned a row that is not understood',
    );
  });

  it('F-53: a position the database cannot read (class 22) is a 400 on query.cursor', async () => {
    const { events } = queriesOver([PROCESS_FOUND, failure('22003', 'bigint out of range')]);

    const error = await events
      .list(P1, { limit: 50, after: { id: '9223372036854775807' } })
      .catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(ValidationError);
    expect((error as ValidationError).issues.map((issue) => issue.path)).toEqual(['query.cursor']);
    expect((error as ValidationError).cause).toEqual({ code: '22003' });
  });

  it('a class 22 error with no position given is not the cursor: an unexpected error', async () => {
    const { events } = queriesOver([PROCESS_FOUND, failure('22003', 'bigint out of range')]);

    const error = await events.list(P1, { limit: 50 }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(Error);
    expect(error).not.toBeInstanceOf(ValidationError);
    expect((error as Error).cause).toEqual({ code: '22003', status: 400 });
  });

  it('E-21: an unreachable database is a ServiceUnavailableError, on every read', async () => {
    const down = failure('', 'fetch failed', 0);
    const scripts: Outcome[][] = [
      [down],
      [PROCESS_FOUND, down],
      [PROCESS_FOUND, answer([eventRow(1, 'stage.approved', null, S1)]), down, answer([])],
      [PROCESS_FOUND, answer([eventRow(1, 'process.created', CEO_ONE)]), down],
    ];
    for (const script of scripts) {
      const { events } = queriesOver(script);
      await expect(events.list(P1, { limit: 50 })).rejects.toBeInstanceOf(ServiceUnavailableError);
    }
  });

  it('an error that is not an outage is an unexpected error, with only code and status as cause', async () => {
    const { events } = queriesOver([
      PROCESS_FOUND,
      failure('XX000', 'internal error near Processo Secreto'),
    ]);

    const error = await events.list(P1, { limit: 50 }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(Error);
    expect((error as Error).cause).toEqual({ code: 'XX000', status: 400 });
    expect(JSON.stringify((error as Error).cause)).not.toContain('Secreto');
  });
});
