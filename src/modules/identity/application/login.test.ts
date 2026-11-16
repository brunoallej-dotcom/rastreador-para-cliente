import { describe, expect, it } from 'vitest';
import { ServiceUnavailableError, type Principal } from '@/shared/kernel';
import { InvalidCredentialsError } from '../domain/errors';
import { createFakeClientDirectory, createFakeIdentity, type FakeAccount } from './fakes';
import { login } from './login';

const CLIENT = { id: '22222222-2222-4222-8222-222222222222', name: 'Cliente A' };

const clientPrincipal: Principal = {
  userId: '11111111-1111-4111-8111-111111111111',
  role: 'client',
  clientId: CLIENT.id,
  displayName: 'Maria',
  aal: 'aal1',
  pendingActions: ['CHANGE_PASSWORD'],
};
const ceoPrincipal: Principal = {
  userId: '33333333-3333-4333-8333-333333333333',
  role: 'ceo',
  clientId: null,
  displayName: 'CEO',
  aal: 'aal1',
  pendingActions: ['CHANGE_PASSWORD', 'ENROLL_MFA'],
};

const PASSWORD = 'correct-horse-battery';
const maria: FakeAccount = {
  email: 'maria@cliente.test',
  password: PASSWORD,
  principal: clientPrincipal,
};
const ceo: FakeAccount = { email: 'ceo@empresa.test', password: PASSWORD, principal: ceoPrincipal };
const disabled: FakeAccount = {
  email: 'bloqueada@cliente.test',
  password: PASSWORD,
  principal: clientPrincipal,
  disabled: true,
};

function setup() {
  const identity = createFakeIdentity([maria, ceo, disabled]);
  const clients = createFakeClientDirectory([CLIENT]);
  return { identity, clients, deps: { auth: identity, principals: identity, clients } };
}

describe('login', () => {
  it('AC-01: signs a client in and returns the principal with its tenant', async () => {
    const { deps, identity } = setup();

    const result = await login(deps, { email: maria.email, password: PASSWORD });

    expect(result).toEqual({ ok: true, value: { principal: clientPrincipal, client: CLIENT } });
    expect(identity.sessionOpen()).toBe(true);
  });

  it('returns a CEO without a tenant and does not look one up', async () => {
    const { deps, clients } = setup();

    const result = await login(deps, { email: ceo.email, password: PASSWORD });

    expect(result).toEqual({ ok: true, value: { principal: ceoPrincipal, client: null } });
    expect(clients.lookups).toEqual([]);
  });

  it('AC-02: a wrong password is InvalidCredentialsError and opens no session', async () => {
    const { deps, identity } = setup();

    const result = await login(deps, { email: maria.email, password: 'wrong-password-123' });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(InvalidCredentialsError);
    expect(identity.sessionOpen()).toBe(false);
  });

  it('AC-02: an unknown e-mail is the same InvalidCredentialsError', async () => {
    const { deps } = setup();

    const result = await login(deps, { email: 'nobody@cliente.test', password: PASSWORD });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(InvalidCredentialsError);
  });

  it('AC-02: a disabled account gets the same error, and the session it opened is revoked', async () => {
    const { deps, identity } = setup();

    const result = await login(deps, { email: disabled.email, password: PASSWORD });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(InvalidCredentialsError);
    expect(identity.calls).toEqual(['signIn', 'current', 'signOut']);
    expect(identity.sessionOpen()).toBe(false);
  });

  it('AC-02: wrong password, unknown e-mail and disabled account are indistinguishable', async () => {
    const { deps } = setup();
    const errors: unknown[] = [];
    for (const credentials of [
      { email: maria.email, password: 'wrong-password-123' },
      { email: 'nobody@cliente.test', password: PASSWORD },
      { email: disabled.email, password: PASSWORD },
    ]) {
      const result = await login(deps, credentials);
      if (!result.ok) errors.push(result.error);
    }

    expect(errors).toHaveLength(3);
    for (const error of errors as InvalidCredentialsError[]) {
      expect(error.code).toBe('INVALID_CREDENTIALS');
      expect(error.detail).toBe((errors[0] as InvalidCredentialsError).detail);
    }
  });

  it('SEC-12: a disabled account still answers 401-style when the cleanup sign-out fails', async () => {
    const { deps, identity } = setup();
    identity.failWith('signOut');

    const result = await login(deps, { email: disabled.email, password: PASSWORD });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(InvalidCredentialsError);
  });

  it('E-21: an outage while signing in propagates as ServiceUnavailableError', async () => {
    const { deps, identity } = setup();
    identity.failWith('signIn');

    await expect(login(deps, { email: maria.email, password: PASSWORD })).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });

  it('revokes the session it opened when reading the principal fails, and rethrows', async () => {
    const { deps, identity } = setup();
    identity.failWith('current');

    await expect(login(deps, { email: maria.email, password: PASSWORD })).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
    expect(identity.sessionOpen()).toBe(false);
    expect(identity.calls).toEqual(['signIn', 'current', 'signOut']);
  });

  it('revokes the session and fails when the tenant of a client user is not readable', async () => {
    const identity = createFakeIdentity([maria]);
    const clients = createFakeClientDirectory([]);

    await expect(
      login(
        { auth: identity, principals: identity, clients },
        { email: maria.email, password: PASSWORD },
      ),
    ).rejects.toThrow('tenant');
    expect(identity.sessionOpen()).toBe(false);
  });
});
