// Invariants of contracts/openapi.v1.yaml that no single endpoint test owns: what EVERY authenticated
// operation documents, and that the programmatic budgets the contract lists are the ones the code
// registers (`PROGRAMMATIC_BUDGETS`), on exactly the operations that spend them, and vice versa.
// The other half of the chain (the registry against the handlers and the source) is
// `src/modules/identity/presentation/programmatic-budgets.test.ts`. The per-operation policy and
// rate-limit checks live next to each handler.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { PROGRAMMATIC_BUDGETS } from '@/modules/identity/presentation/rate-limit-budgets';
import { SESSION_UPSTREAM_RULE } from '@/shared/http/supabase-principal-resolver';

type RateLimitEntry = {
  scope: string;
  group?: string;
  limit: number;
  windowSeconds: number;
  programmatic?: boolean;
};

type Operation = {
  operationId: string;
  'x-auth-policy': { access: string };
  'x-rate-limit'?: RateLimitEntry[];
  responses: Record<string, { $ref?: string }>;
};

type Contract = {
  paths: Record<string, Record<string, Operation>>;
  components: {
    securitySchemes: Record<string, { 'x-rate-limit'?: RateLimitEntry[] }>;
    responses: Record<string, unknown>;
  };
};

const contract = parse(
  readFileSync(fileURLToPath(new URL('../../contracts/openapi.v1.yaml', import.meta.url)), 'utf8'),
) as Contract;

const operations = Object.values(contract.paths).flatMap((item) => Object.values(item));

/** Every programmatic entry of the contract, with the operation or scheme that carries it. */
const programmaticEntries = [
  ...operations.flatMap((operation) =>
    (operation['x-rate-limit'] ?? [])
      .filter(({ programmatic }) => programmatic === true)
      .map((entry) => ({ carrier: operation.operationId, entry })),
  ),
  ...Object.entries(contract.components.securitySchemes).flatMap(([name, scheme]) =>
    (scheme['x-rate-limit'] ?? [])
      .filter(({ programmatic }) => programmatic === true)
      .map((entry) => ({ carrier: name, entry })),
  ),
];

const carriersOf = (group: string) =>
  programmaticEntries
    .filter(({ entry }) => entry.group === group)
    .map(({ carrier }) => carrier)
    .sort();

describe('every authenticated operation documents the fail-closed 503', () => {
  const authenticated = operations.filter(
    (operation) => operation['x-auth-policy'].access === 'authenticated',
  );

  // The 24 operations of the spec (§5) minus the two public ones. A new operation changes this
  // number on purpose: it must come with its 503 (the `it.each` below) and with this line.
  it('there are 22 authenticated operations: all but getHealth and login', () => {
    expect(operations).toHaveLength(24);
    expect(
      operations
        .filter((operation) => operation['x-auth-policy'].access === 'public')
        .map((operation) => operation.operationId)
        .sort(),
    ).toEqual(['getHealth', 'login']);
    expect(authenticated).toHaveLength(22);
  });

  it.each(authenticated.map((operation) => [operation.operationId, operation] as const))(
    '%s: 503 is the shared ServiceUnavailable response (Retry-After included)',
    (_operationId, operation) => {
      expect(operation.responses['503']).toEqual({
        $ref: '#/components/responses/ServiceUnavailable',
      });
    },
  );

  it('the shared response exists and has its Retry-After header', () => {
    expect(contract.components.responses['ServiceUnavailable']).toMatchObject({
      headers: { 'Retry-After': { $ref: '#/components/headers/Retry-After' } },
    });
  });
});

describe('the programmatic budgets of x-rate-limit are the registry of the code (and the registry is the contract)', () => {
  const registry = Object.values(PROGRAMMATIC_BUDGETS);

  it.each(Object.entries(PROGRAMMATIC_BUDGETS))(
    '%s: the contract lists it on exactly the operations that spend it, with its numbers',
    (_name, { scope, budget, spentBy }) => {
      expect(carriersOf(budget.group)).toEqual([...spentBy].sort());
      for (const { entry } of programmaticEntries.filter(
        ({ entry }) => entry.group === budget.group,
      )) {
        expect(entry).toEqual({ scope, programmatic: true, ...budget });
      }
    },
  );

  it("session budget per IP (F-01): in the sessionCookie scheme only, with the numbers of SESSION_UPSTREAM_RULE (it is the resolver's, so it is not in the registry)", () => {
    expect(carriersOf('session-upstream')).toEqual(['sessionCookie']);
    const { entry } = programmaticEntries.find(({ entry }) => entry.group === 'session-upstream')!;
    expect(entry).toEqual({ programmatic: true, ...SESSION_UPSTREAM_RULE });
  });

  it('every programmatic entry of the contract is the registry or the session budget: a budget missing from the registry (so unproven in the handlers) fails here', () => {
    const groups = new Set(programmaticEntries.map(({ entry }) => entry.group));
    expect([...groups].sort()).toEqual(
      [...registry.map(({ budget }) => budget.group), SESSION_UPSTREAM_RULE.group].sort(),
    );
  });

  it('every entry without the mark is a route rule: no group (it is declared in code), and the scope of a route policy', () => {
    for (const operation of operations) {
      for (const entry of operation['x-rate-limit'] ?? []) {
        if (entry.programmatic === true) continue;
        expect(entry.group, operation.operationId).toBeUndefined();
        expect(['ip', 'account', 'user'], operation.operationId).toContain(entry.scope);
      }
    }
  });
});
