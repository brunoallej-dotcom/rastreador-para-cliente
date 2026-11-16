import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { verifyTotpBodySchema } from './verify-totp.schema';

const FACTOR_ID = '33333333-3333-4333-8333-333333333333';

type ContractSchemas = {
  components: {
    schemas: Record<
      string,
      {
        required?: string[];
        additionalProperties?: boolean;
        properties?: Record<string, { deprecated?: boolean; $ref?: string; pattern?: string }>;
      }
    >;
  };
};

const request = (
  parse(
    readFileSync(
      fileURLToPath(new URL('../../../../contracts/openapi.v1.yaml', import.meta.url)),
      'utf8',
    ),
  ) as ContractSchemas
).components.schemas['TotpVerifyRequest'];

describe('verifyTotpBodySchema (TotpVerifyRequest)', () => {
  it('accepts a factor id and six digits', () => {
    const parsed = verifyTotpBodySchema.safeParse({ factorId: FACTOR_ID, code: '012345' });
    expect(parsed.success).toBe(true);
  });

  it('keeps leading zeros: the code is text, never a number', () => {
    const parsed = verifyTotpBodySchema.parse({ factorId: FACTOR_ID, code: '000123' });
    expect(parsed.code).toBe('000123');
  });

  it.each([
    ['five digits', '12345'],
    ['seven digits', '1234567'],
    ['letters', '12345a'],
    ['a leading space', ' 12345'],
    ['a trailing newline', '123456\n'],
    ['full-width digits', '１２３４５６'],
    ['an empty string', ''],
  ])('rejects %s', (_label, code) => {
    expect(verifyTotpBodySchema.safeParse({ factorId: FACTOR_ID, code }).success).toBe(false);
  });

  it('rejects a code that is not text', () => {
    expect(verifyTotpBodySchema.safeParse({ factorId: FACTOR_ID, code: 123456 }).success).toBe(
      false,
    );
  });

  it('rejects a factor id that is not a UUID', () => {
    expect(verifyTotpBodySchema.safeParse({ factorId: 'abc', code: '123456' }).success).toBe(false);
  });

  it('accepts the code alone: factorId is optional (contract 1.0.0-draft.2)', () => {
    const parsed = verifyTotpBodySchema.safeParse({ code: '123456' });
    expect(parsed.success).toBe(true);
    if (parsed.success) expect(parsed.data.factorId).toBeUndefined();
  });

  it('a factorId that is null is not a UUID: 400, not "absent"', () => {
    expect(verifyTotpBodySchema.safeParse({ factorId: null, code: '123456' }).success).toBe(false);
  });

  it('E-14: rejects a missing code and an unknown field (.strict)', () => {
    expect(verifyTotpBodySchema.safeParse({}).success).toBe(false);
    expect(verifyTotpBodySchema.safeParse({ factorId: FACTOR_ID }).success).toBe(false);
    expect(
      verifyTotpBodySchema.safeParse({ factorId: FACTOR_ID, code: '123456', userId: 'x' }).success,
    ).toBe(false);
    expect(verifyTotpBodySchema.safeParse({ code: '123456', userId: 'x' }).success).toBe(false);
  });

  it('never echoes the rejected code in its messages', () => {
    const parsed = verifyTotpBodySchema.safeParse({ factorId: FACTOR_ID, code: '98765x' });
    expect(parsed.success).toBe(false);
    if (!parsed.success) expect(JSON.stringify(parsed.error.issues)).not.toContain('98765x');
  });
});

describe('verifyTotpBodySchema against the contract (TotpVerifyRequest)', () => {
  it('has the same fields: only the code is required, factorId is optional and deprecated, nothing else', () => {
    expect(request?.additionalProperties).toBe(false);
    expect(request?.required).toEqual(['code']);
    expect(Object.keys(request?.properties ?? {}).sort()).toEqual(['code', 'factorId']);
    expect(Object.keys(verifyTotpBodySchema.shape).sort()).toEqual(['code', 'factorId']);
    expect(request?.properties?.['factorId']?.deprecated).toBe(true);
    expect(request?.properties?.['factorId']?.$ref).toBe('#/components/schemas/Uuid');
  });
});
