// Public API of the identity module: the only thing other code may import from it.
// No other MODULE depends on identity (`tracking` never may); the HTTP handlers are reached by
// `route.ts` through their own paths (ADR 0005). What is exported here is for the operational
// scripts outside `src/` (`scripts/create-ceo.ts`): pure domain functions, no I/O.
export { normalizeEmail } from './domain/email';
export {
  generateTemporaryPassword,
  TEMPORARY_PASSWORD_LENGTH,
  type RandomBytes,
} from './domain/temporary-password';
