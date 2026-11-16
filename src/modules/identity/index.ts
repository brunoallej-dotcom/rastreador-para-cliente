// Public API of the identity module: the only thing other modules may import from it.
// Nothing is exported yet: no other module depends on identity (`tracking` never may), and the
// HTTP handlers are reached by `route.ts` through their own paths (ADR 0005).
export {};
