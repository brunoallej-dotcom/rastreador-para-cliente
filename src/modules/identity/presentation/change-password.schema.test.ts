import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { PASSWORD_MAX_BYTES, PASSWORD_MIN_CHARACTERS } from '../domain/password-policy';
import { changePasswordBodySchema } from './change-password.schema';

const VALID = { currentPassword: 'the-current-one', newPassword: 'a-new-password-12' };

type ContractSchemas = {
  components: {
    schemas: Record<
      string,
      {
        required?: string[];
        additionalProperties?: boolean;
        properties?: Record<string, { minLength?: number; maxLength?: number }>;
      }
    >;
  };
};

const contract = parse(
  readFileSync(
    fileURLToPath(new URL('../../../../contracts/openapi.v1.yaml', import.meta.url)),
    'utf8',
  ),
) as ContractSchemas;
const request = contract.components.schemas['ChangePasswordRequest'];

describe('changePasswordBodySchema', () => {
  it('accepts both passwords as given, without trimming or normalizing them', () => {
    const parsed = changePasswordBodySchema.parse({
      currentPassword: '  spaces around  ',
      newPassword: 'café-café-café',
    });
    expect(parsed).toEqual({
      currentPassword: '  spaces around  ',
      newPassword: 'café-café-café',
    });
  });

  it('SEC-06: rejects unknown fields (.strict()), role and app_metadata included (AC-31)', () => {
    for (const extra of [{ role: 'ceo' }, { app_metadata: { role: 'ceo' } }, { userId: 'x' }]) {
      expect(changePasswordBodySchema.safeParse({ ...VALID, ...extra }).success).toBe(false);
    }
  });

  it.each([
    ['a missing current password', { newPassword: VALID.newPassword }],
    ['a missing new password', { currentPassword: VALID.currentPassword }],
    ['an empty current password', { ...VALID, currentPassword: '' }],
    ['a non-string current password', { ...VALID, currentPassword: 12345 }],
    ['a non-string new password', { ...VALID, newPassword: ['a-new-password-12'] }],
    ['a null new password', { ...VALID, newPassword: null }],
  ])('rejects %s', (_label, body) => {
    expect(changePasswordBodySchema.safeParse(body).success).toBe(false);
  });

  it('the current password has the size limits of the contract: 1 to 72 BYTES', () => {
    const accepts = (currentPassword: string) =>
      changePasswordBodySchema.safeParse({ ...VALID, currentPassword }).success;
    expect(accepts('x')).toBe(true);
    expect(accepts('x'.repeat(72))).toBe(true);
    expect(accepts('x'.repeat(73))).toBe(false);
    // 36 two-byte letters are 72 bytes; 37 are 74
    expect(accepts('é'.repeat(36))).toBe(true);
    expect(accepts('é'.repeat(37))).toBe(false);
  });

  it('E-12: the NEW password is not size-checked here: a short or long one reaches the policy, which answers 422 and not 400', () => {
    const accepts = (newPassword: string) =>
      changePasswordBodySchema.safeParse({ ...VALID, newPassword }).success;
    expect(accepts('')).toBe(true);
    expect(accepts('short')).toBe(true);
    expect(accepts('x'.repeat(73))).toBe(true);
    expect(accepts('x'.repeat(5000))).toBe(true);
  });

  it('does not echo a rejected value in its messages', () => {
    const secret = 'x'.repeat(80);
    const result = changePasswordBodySchema.safeParse({ ...VALID, currentPassword: secret });
    expect(result.success).toBe(false);
    if (!result.success) expect(JSON.stringify(result.error.issues)).not.toContain(secret);
  });
});

describe('changePasswordBodySchema against the contract (ChangePasswordRequest)', () => {
  it('has the same fields, both required, and no others', () => {
    expect(request?.additionalProperties).toBe(false);
    expect(request?.required?.slice().sort()).toEqual(['currentPassword', 'newPassword']);
    expect(Object.keys(request?.properties ?? {}).sort()).toEqual([
      'currentPassword',
      'newPassword',
    ]);
    expect(Object.keys(changePasswordBodySchema.shape).sort()).toEqual([
      'currentPassword',
      'newPassword',
    ]);
  });

  it('currentPassword: the limits are the contract limits', () => {
    expect(request?.properties?.['currentPassword']).toMatchObject({
      minLength: 1,
      maxLength: PASSWORD_MAX_BYTES,
    });
  });

  it('newPassword: the contract limits ARE the password policy; the schema leaves their enforcement to it', () => {
    expect(request?.properties?.['newPassword']).toMatchObject({
      minLength: PASSWORD_MIN_CHARACTERS,
      maxLength: PASSWORD_MAX_BYTES,
    });
  });
});
