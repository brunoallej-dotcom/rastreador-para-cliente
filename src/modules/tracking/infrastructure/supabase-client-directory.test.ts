import type { SupabaseClient } from '@supabase/supabase-js';
import { describe, expect, it } from 'vitest';
import type { Database } from '@/shared/db/database.types';
import { ServiceUnavailableError } from '@/shared/kernel';
import { getClientSummary } from './supabase-client-directory';

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

describe('getClientSummary', () => {
  it('SEC-06: reads id and name of one client by id, with an explicit column list', async () => {
    const { supabase, calls } = fakeSupabase({
      data: { id: CLIENT_ID, name: 'Cliente A', archived_at: null },
      error: null,
      status: 200,
    });

    await expect(getClientSummary(supabase, CLIENT_ID)).resolves.toEqual({
      id: CLIENT_ID,
      name: 'Cliente A',
    });
    expect(calls).toEqual([
      ['from', 'clients'],
      ['select', 'id, name'],
      ['eq', 'id', CLIENT_ID],
      ['retry', false],
      ['maybeSingle'],
    ]);
  });

  it('SEC-05: a row RLS hides is null, not an error', async () => {
    const { supabase } = fakeSupabase({ data: null, error: null, status: 200 });
    await expect(getClientSummary(supabase, CLIENT_ID)).resolves.toBeNull();
  });

  it('E-21: Supabase being down is ServiceUnavailableError', async () => {
    const { supabase } = fakeSupabase({
      data: null,
      error: { message: 'TypeError: fetch failed', code: '' },
      status: 0,
    });
    await expect(getClientSummary(supabase, CLIENT_ID)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it('denies on any other database error, without echoing it', async () => {
    const { supabase } = fakeSupabase({
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
    const { supabase } = fakeSupabase({ data, error: null, status: 200 });
    await expect(getClientSummary(supabase, CLIENT_ID)).rejects.toThrow('not understood');
  });
});
