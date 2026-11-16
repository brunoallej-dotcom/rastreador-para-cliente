// Invariants of contracts/openapi.v1.yaml that no single endpoint test owns: what EVERY authenticated
// operation documents, and that the programmatic budgets the contract lists are the ones the code
// spends (and vice versa). The per-operation policy and rate-limit checks live next to each handler.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import {
  LOGIN_GLOBAL_BUDGET,
  VERIFY_DAILY_BUDGET,
} from '@/modules/identity/presentation/rate-limit-budgets';
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

  it('there are authenticated operations to check', () => {
    expect(authenticated.length).toBeGreaterThanOrEqual(20);
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

describe('the programmatic budgets of x-rate-limit are the ones the code spends', () => {
  it('login global cap (F-02): in login and changePassword (the proof of the current password is a sign-in), with the numbers of LOGIN_GLOBAL_BUDGET', () => {
    expect(carriersOf('login')).toEqual(['changePassword', 'login']);
    for (const { entry } of programmaticEntries.filter(({ entry }) => entry.group === 'login')) {
      expect(entry).toEqual({ scope: 'global', programmatic: true, ...LOGIN_GLOBAL_BUDGET });
    }
  });

  it('TOTP daily cap (F-22): in verifyTotp only, with the numbers of VERIFY_DAILY_BUDGET', () => {
    expect(carriersOf('totp-verify-daily')).toEqual(['verifyTotp']);
    const { entry } = programmaticEntries.find(({ entry }) => entry.group === 'totp-verify-daily')!;
    expect(entry).toEqual({ scope: 'user', programmatic: true, ...VERIFY_DAILY_BUDGET });
  });

  it('session budget per IP (F-01): in the sessionCookie scheme only, with the numbers of SESSION_UPSTREAM_RULE', () => {
    expect(carriersOf('session-upstream')).toEqual(['sessionCookie']);
    const { entry } = programmaticEntries.find(({ entry }) => entry.group === 'session-upstream')!;
    expect(entry).toEqual({ programmatic: true, ...SESSION_UPSTREAM_RULE });
  });

  it('there is no other programmatic entry: a new budget in the code needs a line in the contract (and in this test)', () => {
    const groups = new Set(programmaticEntries.map(({ entry }) => entry.group));
    expect([...groups].sort()).toEqual(['login', 'session-upstream', 'totp-verify-daily']);
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
