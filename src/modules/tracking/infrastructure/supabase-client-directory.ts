import type { SupabaseClient } from '@supabase/supabase-js';
import { z } from 'zod';
import type { Database } from '@/shared/db/database.types';
import { upstreamFailure } from '@/shared/db/upstream-errors';

/** What other modules may know about a client (tenant): its id and its name. */
export type ClientSummary = { readonly id: string; readonly name: string };

const clientSummarySchema = z.object({ id: z.guid(), name: z.string() });

/**
 * Reads one client as the signed-in user. RLS decides who sees what: a client user sees only their
 * own tenant's row and a CEO with an `aal2` session sees all of them, so a row that is not visible
 * comes back as `null` (never as an error).
 *
 * Takes the request-scoped client (never the admin client). Throws `ServiceUnavailableError`
 * when Supabase is slow or down (E-21) and a plain `Error` (500) for anything unexpected.
 */
export async function getClientSummary(
  supabase: SupabaseClient<Database>,
  clientId: string,
): Promise<ClientSummary | null> {
  const { data, error, status } = await supabase
    .from('clients')
    .select('id, name')
    .eq('id', clientId)
    // postgrest-js retries a GET with backoff on its own (about 7 s on a dead upstream): without
    // this the 5 s bound of E-21 would not hold.
    .retry(false)
    .maybeSingle();
  if (error) throw upstreamFailure('read the client', error, status);
  if (data === null) return null;

  const summary = clientSummarySchema.safeParse(data);
  if (!summary.success) throw new Error('the clients table returned a row that is not understood');
  return { id: summary.data.id, name: summary.data.name };
}
