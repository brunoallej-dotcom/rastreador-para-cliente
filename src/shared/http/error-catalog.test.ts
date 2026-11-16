import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import { describe, expect, it } from 'vitest';
import { ERROR_CODES, type ErrorCode } from '@/shared/kernel';
import { ERROR_CATALOG } from './error-catalog';

type Contract = { components: { schemas: { ErrorCode: { enum: string[] } } } };

const contract = parse(
  readFileSync(
    fileURLToPath(new URL('../../../contracts/openapi.v1.yaml', import.meta.url)),
    'utf8',
  ),
) as Contract;

/** Spec §5, "Catálogo de code": HTTP status → codes. Independent from the catalog under test. */
const SPEC_STATUS_TABLE: Readonly<Record<number, readonly ErrorCode[]>> = {
  400: ['VALIDATION_ERROR'],
  401: ['UNAUTHENTICATED', 'INVALID_CREDENTIALS'],
  403: [
    'FORBIDDEN',
    'ORIGIN_NOT_ALLOWED',
    'PASSWORD_CHANGE_REQUIRED',
    'MFA_ENROLLMENT_REQUIRED',
    'MFA_VERIFICATION_REQUIRED',
  ],
  404: ['NOT_FOUND'],
  409: ['STALE_STAGE', 'EMAIL_ALREADY_REGISTERED', 'MFA_ALREADY_ENROLLED', 'CONFLICT'],
  413: ['PAYLOAD_TOO_LARGE'],
  415: ['UNSUPPORTED_MEDIA_TYPE'],
  422: [
    'PROCESS_NOT_ACTIVE',
    'CLIENT_ARCHIVED',
    'WEAK_PASSWORD',
    'PASSWORD_UNCHANGED',
    'INVALID_CURRENT_PASSWORD',
    'INVALID_MFA_CODE',
    'USER_LIMIT_REACHED',
  ],
  429: ['RATE_LIMITED'],
  500: ['INTERNAL_ERROR'],
  503: ['SERVICE_UNAVAILABLE'],
};

describe('ERROR_CATALOG', () => {
  it('has exactly the codes of components.schemas.ErrorCode of the contract (no more, no fewer)', () => {
    const contractCodes = contract.components.schemas.ErrorCode.enum;
    expect(Object.keys(ERROR_CATALOG).sort()).toEqual([...contractCodes].sort());
    expect(Object.keys(ERROR_CATALOG)).toHaveLength(contractCodes.length);
    expect(Object.keys(ERROR_CATALOG).sort()).toEqual([...ERROR_CODES].sort());
  });

  it('maps every code to the HTTP status of spec §5', () => {
    const fromSpec = Object.entries(SPEC_STATUS_TABLE).flatMap(([status, codes]) =>
      codes.map((code) => [code, Number(status)] as const),
    );
    expect(fromSpec).toHaveLength(ERROR_CODES.length);
    for (const [code, status] of fromSpec) {
      expect(ERROR_CATALOG[code].status, code).toBe(status);
    }
  });

  it('keeps statuses inside the Problem.status range of the contract (400..599)', () => {
    for (const { status } of Object.values(ERROR_CATALOG)) {
      expect(status).toBeGreaterThanOrEqual(400);
      expect(status).toBeLessThanOrEqual(599);
    }
  });

  it('gives every code a short non-empty title (Problem.title maxLength 200)', () => {
    for (const { title } of Object.values(ERROR_CATALOG)) {
      expect(title.length).toBeGreaterThan(0);
      expect(title.length).toBeLessThanOrEqual(200);
    }
  });
});
