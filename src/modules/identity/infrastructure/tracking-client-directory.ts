import type { RequestSupabase } from '@/shared/db/server-client';
import { getClientStatus, getClientSummary } from '@/modules/tracking';
import type { ClientStatusDirectory } from '../domain/client-user-ports';
import type { ClientDirectory } from '../domain/ports';

/**
 * `ClientDirectory` over the tracking module's public index (the only door between the modules:
 * identity knows a client id as an opaque value and asks tracking for the rest).
 */
export function createTrackingClientDirectory(supabase: RequestSupabase): ClientDirectory {
  return {
    find: (clientId) => getClientSummary(supabase, clientId),
  };
}

/**
 * `ClientStatusDirectory` over the same index: the client with its `archived` flag, read as the CEO
 * who is calling (RLS decides what is visible). It lets the provisioning answer 422 `CLIENT_ARCHIVED`
 * before creating anything; the profile trigger of the database remains the deciding check (F-58).
 */
export function createTrackingClientStatusDirectory(
  supabase: RequestSupabase,
): ClientStatusDirectory {
  return {
    status: (clientId) => getClientStatus(supabase, clientId),
  };
}
