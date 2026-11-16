// Public API of the tracking module: the only thing other modules may import from it.
// `identity` reads a client through these two functions (Wave 3: `getClientSummary` for the session,
// Wave 6: `getClientStatus` so Wave 7 can refuse a login for an archived client); `tracking` never
// imports `identity`.
export {
  getClientStatus,
  getClientSummary,
  type ClientStatus,
  type ClientSummary,
} from './infrastructure/supabase-client-directory';
