import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';
import { loginBodySchema } from './login.schema';

const VALID = { email: 'maria@cliente.test', password: 'a-password' };

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

describe('loginBodySchema', () => {
  it('E-11: normalizes the e-mail (trim, NFC, lowercase) in its OUTPUT', () => {
    const parsed = loginBodySchema.parse({ email: '  Maria@Cliente.TEST ', password: 'x' });
    expect(parsed.email).toBe('maria@cliente.test');
  });

  it('SEC-06: rejects unknown fields (.strict())', () => {
    const result = loginBodySchema.safeParse({ ...VALID, role: 'ceo' });
    expect(result.success).toBe(false);
  });

  it.each([
    ['a missing e-mail', { password: 'x' }],
    ['a missing password', { email: VALID.email }],
    ['an empty password', { ...VALID, password: '' }],
    ['a non-string password', { ...VALID, password: 12345 }],
    ['a non-string e-mail', { ...VALID, email: ['a@b.test'] }],
    ['an e-mail that is not an address', { ...VALID, email: 'not-an-email' }],
    ['an e-mail with a space inside', { ...VALID, email: 'ma ria@cliente.test' }],
    ['an empty e-mail', { ...VALID, email: '   ' }],
  ])('rejects %s', (_label, body) => {
    expect(loginBodySchema.safeParse(body).success).toBe(false);
  });

  it('E-12: the password has only size limits: 1 to 72 BYTES, no policy, no trimming', () => {
    expect(loginBodySchema.parse({ ...VALID, password: 'x' }).password).toBe('x');
    expect(loginBodySchema.parse({ ...VALID, password: 'x'.repeat(72) }).password).toHaveLength(72);
    expect(loginBodySchema.safeParse({ ...VALID, password: 'x'.repeat(73) }).success).toBe(false);
    // 36 two-byte letters are 72 bytes; 37 are 74
    expect(loginBodySchema.safeParse({ ...VALID, password: 'é'.repeat(36) }).success).toBe(true);
    expect(loginBodySchema.safeParse({ ...VALID, password: 'é'.repeat(37) }).success).toBe(false);
    // a short or weak password is a wrong password, not a 400
    expect(loginBodySchema.safeParse({ ...VALID, password: 'abc' }).success).toBe(true);
    expect(loginBodySchema.parse({ ...VALID, password: '  spaces  ' }).password).toBe('  spaces  ');
  });

  it('the e-mail is at most 254 characters', () => {
    const local = 'a'.repeat(64);
    const domain = `${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(56)}.test`;
    const atLimit = `${local}@${domain}`;
    expect(atLimit.length).toBe(254);
    expect(loginBodySchema.safeParse({ ...VALID, email: atLimit }).success).toBe(true);
    expect(loginBodySchema.safeParse({ ...VALID, email: `x${atLimit}` }).success).toBe(false);
  });

  it('AC-26: has the same fields, requirements and limits as LoginRequest in the contract', () => {
    const request = contract.components.schemas['LoginRequest'];
    expect(request?.additionalProperties).toBe(false);
    expect(request?.required).toEqual(['email', 'password']);
    expect(Object.keys(request?.properties ?? {}).sort()).toEqual(['email', 'password']);
    expect(request?.properties?.['password']).toMatchObject({ minLength: 1, maxLength: 72 });
    expect(contract.components.schemas['Email']).toMatchObject({ maxLength: 254 });
  });
});
