import type { RequestSupabase } from '@/shared/db/server-client';
import { getClientSummary } from '@/modules/tracking';
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
