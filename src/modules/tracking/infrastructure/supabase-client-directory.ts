import type { SupabaseClient } from '@supabase/supabase-js';
import { z } from 'zod';
import type { Database } from '@/shared/db/database.types';
import { upstreamFailure } from '@/shared/db/upstream-errors';
import { timestampSchema } from './timestamp-schema';

/** What other modules may know about a client (tenant): its id and its name. */
export type ClientSummary = { readonly id: string; readonly name: string };

/**
 * What `identity` needs to decide about a client (Wave 7: no new login for an archived client): the
 * summary plus whether the client is archived.
 */
export type ClientStatus = ClientSummary & { readonly archived: boolean };

const clientStatusRowSchema = z.object({
  id: z.guid(),
  name: z.string(),
  archived_at: timestampSchema.nullable(),
});

/**
 * Reads one client as the signed-in user. RLS decides who sees what: a client user sees only their
 * own tenant's row and a CEO with an `aal2` session sees all of them, so a row that is not visible
 * comes back as `null` (never as an error).
 *
 * Takes the request-scoped client (never the admin client). Throws `ServiceUnavailableError`
 * when Supabase is slow or down (E-21) and a plain `Error` (500) for anything unexpected.
 */
export async function getClientStatus(
  supabase: SupabaseClient<Database>,
  clientId: string,
): Promise<ClientStatus | null> {
  const { data, error, status } = await supabase
    .from('clients')
    .select('id, name, archived_at')
    .eq('id', clientId)
    // postgrest-js retries a GET with backoff on its own (about 7 s on a dead upstream): without
    // this the 5 s bound of E-21 would not hold.
    .retry(false)
    .maybeSingle();
  if (error) throw upstreamFailure('read the client', error, status);
  if (data === null) return null;

  const row = clientStatusRowSchema.safeParse(data);
  if (!row.success) throw new Error('the clients table returned a row that is not understood');
  return { id: row.data.id, name: row.data.name, archived: row.data.archived_at !== null };
}

const clientSummaryRowSchema = z.object({ id: z.guid(), name: z.string() });

/**
 * The client of the signed-in LOGIN, as a session shows it (`SessionClient`: id and name). It asks the
 * database function `current_client_summary()`, not the `clients` table: the login of a client with the
 * temporary password still pending has a principal and a session, and its sign-in answer names the client,
 * but the RLS no longer lets it read ANY tracking table (F-83), `clients` included. The function answers
 * about the caller's OWN client only (it takes no argument), so `clientId`, the one of the principal, is
 * compared with the answer: anything else is `null`, never another client.
 *
 * Takes the request-scoped client (never the admin client). Throws `ServiceUnavailableError` when Supabase
 * is slow or down (E-21) and a plain `Error` (500) for anything unexpected.
 */
export async function getClientSummary(
  supabase: SupabaseClient<Database>,
  clientId: string,
): Promise<ClientSummary | null> {
  const { data, error, status } = await supabase.rpc('current_client_summary').maybeSingle();
  if (error) throw upstreamFailure('read the client', error, status);
  if (data === null) return null;

  const row = clientSummaryRowSchema.safeParse(data);
  if (!row.success) {
    throw new Error('current_client_summary() returned a row that is not understood');
  }
  return row.data.id === clientId ? { id: row.data.id, name: row.data.name } : null;
}
