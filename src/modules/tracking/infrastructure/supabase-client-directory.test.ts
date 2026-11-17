import type { SupabaseClient } from '@supabase/supabase-js';
import { describe, expect, it } from 'vitest';
import type { Database } from '@/shared/db/database.types';
import { ServiceUnavailableError } from '@/shared/kernel';
import { getClientStatus, getClientSummary } from './supabase-client-directory';

const CLIENT_ID = '22222222-2222-4222-8222-222222222222';

type Outcome = { data: unknown; error: unknown; status: number };

/** Records the query chain and answers a scripted outcome. */
function fakeSupabase(outcome: Outcome) {
  const calls: unknown[][] = [];
  const query = {
    select: (...args: unknown[]) => {
      calls.push(['select', ...args]);
      return query;
    },
    eq: (...args: unknown[]) => {
      calls.push(['eq', ...args]);
      return query;
    },
    retry: (...args: unknown[]) => {
      calls.push(['retry', ...args]);
      return query;
    },
    maybeSingle: () => {
      calls.push(['maybeSingle']);
      return Promise.resolve(outcome);
    },
  };
  const supabase = {
    from: (table: string) => {
      calls.push(['from', table]);
      return query;
    },
  } as unknown as SupabaseClient<Database>;
  return { supabase, calls };
}

/** Records the rpc call and answers a scripted outcome (`current_client_summary()`). */
function fakeRpcSupabase(outcome: Outcome) {
  const calls: unknown[][] = [];
  const query = {
    maybeSingle: () => {
      calls.push(['maybeSingle']);
      return Promise.resolve(outcome);
    },
  };
  const supabase = {
    rpc: (...args: unknown[]) => {
      calls.push(['rpc', ...args]);
      return query;
    },
  } as unknown as SupabaseClient<Database>;
  return { supabase, calls };
}

describe('getClientSummary', () => {
  it('F-83: reads the client of the login through current_client_summary(), never the table, and answers id and name', async () => {
    const { supabase, calls } = fakeRpcSupabase({
      data: { id: CLIENT_ID, name: 'Cliente A' },
      error: null,
      status: 200,
    });

    await expect(getClientSummary(supabase, CLIENT_ID)).resolves.toEqual({
      id: CLIENT_ID,
      name: 'Cliente A',
    });
    // no argument: no id from outside chooses the row, and no `from('clients')`
    expect(calls).toEqual([['rpc', 'current_client_summary'], ['maybeSingle']]);
  });

  it('SEC-05: no row (a CEO, a dead session, a disabled login) is null, not an error', async () => {
    const { supabase } = fakeRpcSupabase({ data: null, error: null, status: 200 });
    await expect(getClientSummary(supabase, CLIENT_ID)).resolves.toBeNull();
  });

  it('answers null, never another client, when the function names a client that is not the one asked for', async () => {
    const { supabase } = fakeRpcSupabase({
      data: { id: '33333333-3333-4333-8333-333333333333', name: 'Cliente B' },
      error: null,
      status: 200,
    });
    await expect(getClientSummary(supabase, CLIENT_ID)).resolves.toBeNull();
  });

  it('E-21: Supabase being down is ServiceUnavailableError', async () => {
    const { supabase } = fakeRpcSupabase({
      data: null,
      error: { message: 'TypeError: fetch failed', code: '' },
      status: 0,
    });
    await expect(getClientSummary(supabase, CLIENT_ID)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it('denies on any other database error, without echoing it', async () => {
    const { supabase } = fakeRpcSupabase({
      data: null,
      error: { message: 'internal detail', code: '42501' },
      status: 403,
    });
    const rejection = getClientSummary(supabase, CLIENT_ID);
    await expect(rejection).rejects.toThrow('read the client failed unexpectedly');
    await expect(rejection).rejects.not.toBeInstanceOf(ServiceUnavailableError);
  });

  it.each([
    ['a row without a name', { id: CLIENT_ID }],
    ['an id that is not a UUID', { id: 'nope', name: 'Cliente A' }],
  ])('fails closed on %s', async (_label, data) => {
    const { supabase } = fakeRpcSupabase({ data, error: null, status: 200 });
    await expect(getClientSummary(supabase, CLIENT_ID)).rejects.toThrow('not understood');
  });
});

describe('getClientStatus', () => {
  it('reports an active client as not archived', async () => {
    const { supabase, calls } = fakeSupabase({
      data: { id: CLIENT_ID, name: 'Cliente A', archived_at: null },
      error: null,
      status: 200,
    });

    await expect(getClientStatus(supabase, CLIENT_ID)).resolves.toEqual({
      id: CLIENT_ID,
      name: 'Cliente A',
      archived: false,
    });
    expect(calls).toContainEqual(['select', 'id, name, archived_at']);
    expect(calls).toContainEqual(['retry', false]);
  });

  it('AC-11: reports an archived client as archived', async () => {
    const { supabase } = fakeSupabase({
      data: { id: CLIENT_ID, name: 'Cliente A', archived_at: '2026-11-16T10:00:00.123456+00:00' },
      error: null,
      status: 200,
    });

    await expect(getClientStatus(supabase, CLIENT_ID)).resolves.toEqual({
      id: CLIENT_ID,
      name: 'Cliente A',
      archived: true,
    });
  });

  it('SEC-05: a row RLS hides is null, not an error', async () => {
    const { supabase } = fakeSupabase({ data: null, error: null, status: 200 });
    await expect(getClientStatus(supabase, CLIENT_ID)).resolves.toBeNull();
  });

  it('E-21: Supabase being down is ServiceUnavailableError', async () => {
    const { supabase } = fakeSupabase({
      data: null,
      error: { message: 'TypeError: fetch failed', code: '' },
      status: 0,
    });
    await expect(getClientStatus(supabase, CLIENT_ID)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it('fails closed on a row without the archived column', async () => {
    const { supabase } = fakeSupabase({
      data: { id: CLIENT_ID, name: 'Cliente A' },
      error: null,
      status: 200,
    });
    await expect(getClientStatus(supabase, CLIENT_ID)).rejects.toThrow('not understood');
  });
});
