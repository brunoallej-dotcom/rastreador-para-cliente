import { describe, expect, it } from 'vitest';
import { ServiceUnavailableError, type Principal } from '@/shared/kernel';
import { createFakeIdentity } from './fakes';
import { login } from './login';
import { logout } from './logout';
import { createFakeClientDirectory } from './fakes';

const principal: Principal = {
  userId: '33333333-3333-4333-8333-333333333333',
  role: 'ceo',
  clientId: null,
  displayName: 'CEO',
  aal: 'aal1',
  pendingActions: ['CHANGE_PASSWORD', 'ENROLL_MFA'],
};
const account = { email: 'ceo@empresa.test', password: 'correct-horse-battery', principal };

describe('logout', () => {
  it('AC-04: revokes the session of the request', async () => {
    const identity = createFakeIdentity([account]);
    const deps = { auth: identity, principals: identity, clients: createFakeClientDirectory([]) };
    await login(deps, { email: account.email, password: account.password });
    expect(identity.sessionOpen()).toBe(true);

    const result = await logout({ auth: identity });

    expect(result).toEqual({ ok: true, value: undefined });
    expect(identity.sessionOpen()).toBe(false);
  });

  it('E-21: does not report a logout whose revocation could not be confirmed', async () => {
    const identity = createFakeIdentity([account]);
    identity.failWith('signOut');

    await expect(logout({ auth: identity })).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
