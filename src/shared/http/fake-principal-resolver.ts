import type { Principal } from '@/shared/kernel';
import type { PrincipalResolver, ResolvePrincipalInput } from './principal-resolver';

export type FakePrincipalSource =
  | Principal
  | null
  | ((input: ResolvePrincipalInput) => Principal | null | Promise<Principal | null>);

export type FakePrincipalResolver = PrincipalResolver & {
  /** One entry per `resolve` call, so tests can prove authentication did or did not run. */
  readonly calls: ResolvePrincipalInput[];
};

/**
 * In-memory resolver for tests: always the same principal (or `null` for "no session"), or
 * whatever a function decides from the request. A function that throws simulates an outage.
 * It records every call, so do not use it in production wiring (use `noPrincipalResolver`).
 */
export function createFakePrincipalResolver(
  source: FakePrincipalSource = null,
): FakePrincipalResolver {
  const calls: ResolvePrincipalInput[] = [];
  return {
    calls,
    async resolve(input) {
      calls.push(input);
      return typeof source === 'function' ? await source(input) : source;
    },
  };
}

/**
 * Resolver that never finds a session. It is the production default until the Supabase resolver
 * is wired in (Wave 3): authenticated routes answer 401, public routes are unaffected.
 */
export const noPrincipalResolver: PrincipalResolver = {
  resolve: () => Promise.resolve(null),
};
