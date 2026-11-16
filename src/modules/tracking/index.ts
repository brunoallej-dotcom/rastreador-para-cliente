// Public API of the tracking module: the only thing other modules may import from it.
// Wave 6 adds `getClientStatus` here; `tracking` never imports `identity`.
export { getClientSummary, type ClientSummary } from './infrastructure/supabase-client-directory';
