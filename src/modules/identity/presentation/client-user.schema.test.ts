import { describe, expect, it } from 'vitest';
import {
  clientIdParamsSchema,
  clientUserParamsSchema,
  provisionClientUserBodySchema,
  updateClientUserBodySchema,
} from './client-user.schema';

const UUID = '33333333-3333-4333-8333-333333333333';
const COMBINING_ACUTE = String.fromCodePoint(0x0301);
const E_ACUTE = String.fromCodePoint(0x00e9);

describe('provisionClientUserBodySchema', () => {
  it('E-11: the e-mail is trimmed and lowercased, and the same address in any spelling is one value', () => {
    const parse = (email: string) =>
      provisionClientUserBodySchema.parse({ email, displayName: 'Maria' }).email;

    expect(parse('  Maria.Souza@Cliente.COM ')).toBe('maria.souza@cliente.com');
    expect(parse('MARIA.SOUZA@CLIENTE.COM')).toBe(parse('maria.souza@cliente.com'));
  });

  it('E-30: the display name is NFC and trimmed', () => {
    const parsed = provisionClientUserBodySchema.parse({
      email: 'a@cliente.test',
      displayName: `  Jos${'e'}${COMBINING_ACUTE} `,
    });

    expect(parsed.displayName).toBe(`Jos${E_ACUTE}`);
  });

  it('accepts a name of 120 characters and refuses 121 (the contract)', () => {
    const accepts = (name: string) =>
      provisionClientUserBodySchema.safeParse({ email: 'a@cliente.test', displayName: name })
        .success;

    expect(accepts('a'.repeat(120))).toBe(true);
    expect(accepts('a'.repeat(121))).toBe(false);
  });

  it('refuses hidden characters, a name with no letter and an address of more than 254 characters', () => {
    const accepts = (email: string, name: string) =>
      provisionClientUserBodySchema.safeParse({ email, displayName: name }).success;

    expect(accepts('a@cliente.test', `Ma${String.fromCodePoint(0x200b)}ria`)).toBe(false);
    expect(accepts('a@cliente.test', '!!!')).toBe(false);
    expect(accepts(`${'a'.repeat(250)}@cliente.test`, 'Maria')).toBe(false);
    expect(accepts('not-an-address', 'Maria')).toBe(false);
  });

  it('AC-23: .strict(): role, clientId, password and anything else are refused', () => {
    for (const extra of [
      { role: 'ceo' },
      { clientId: UUID },
      { password: 'x'.repeat(20) },
      { temporaryPassword: 'x'.repeat(20) },
    ]) {
      const parsed = provisionClientUserBodySchema.safeParse({
        email: 'a@cliente.test',
        displayName: 'Maria',
        ...extra,
      });
      expect(parsed.success).toBe(false);
    }
  });
});

describe('updateClientUserBodySchema', () => {
  it('accepts disabled alone, displayName alone, or both', () => {
    expect(updateClientUserBodySchema.safeParse({ disabled: false }).success).toBe(true);
    expect(updateClientUserBodySchema.safeParse({ displayName: 'Maria' }).success).toBe(true);
    expect(
      updateClientUserBodySchema.safeParse({ disabled: true, displayName: 'Maria' }).success,
    ).toBe(true);
  });

  it('minProperties 1: an empty body is refused', () => {
    expect(updateClientUserBodySchema.safeParse({}).success).toBe(false);
  });

  it('AC-23: .strict(): email, role, clientId and password are refused', () => {
    for (const extra of [{ email: 'b@cliente.test' }, { role: 'ceo' }, { clientId: UUID }]) {
      expect(updateClientUserBodySchema.safeParse({ disabled: true, ...extra }).success).toBe(
        false,
      );
    }
  });
});

describe('path parameters', () => {
  it('E-06: only UUIDs, and nothing else in the object', () => {
    expect(clientIdParamsSchema.safeParse({ clientId: UUID }).success).toBe(true);
    expect(clientIdParamsSchema.safeParse({ clientId: 'x' }).success).toBe(false);
    expect(clientUserParamsSchema.safeParse({ clientId: UUID, userId: UUID }).success).toBe(true);
    expect(clientUserParamsSchema.safeParse({ clientId: UUID, userId: 'x' }).success).toBe(false);
    expect(clientUserParamsSchema.safeParse({ clientId: UUID }).success).toBe(false);
    expect(
      clientUserParamsSchema.safeParse({ clientId: UUID, userId: UUID, extra: 1 }).success,
    ).toBe(false);
  });
});
