import { describe, expect, it } from 'vitest';
import type { Principal } from '@/shared/kernel';
import { createFakeClientDirectory } from './fakes';
import { getSession } from './get-session';

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
  aal: 'aal2',
  pendingActions: [],
};

describe('getSession', () => {
  it('SEC-03: the tenant of a client user comes from the principal, not from the request', async () => {
    const clients = createFakeClientDirectory([CLIENT, { id: 'other', name: 'Cliente B' }]);

    const result = await getSession({ clients }, clientPrincipal);

    expect(result).toEqual({ ok: true, value: { principal: clientPrincipal, client: CLIENT } });
    expect(clients.lookups).toEqual([CLIENT.id]);
  });

  it('a CEO has no tenant, and no lookup happens', async () => {
    const clients = createFakeClientDirectory([CLIENT]);

    const result = await getSession({ clients }, ceoPrincipal);

    expect(result).toEqual({ ok: true, value: { principal: ceoPrincipal, client: null } });
    expect(clients.lookups).toEqual([]);
  });

  it('fails (500) instead of guessing when the tenant of a client user is not readable', async () => {
    const clients = createFakeClientDirectory([]);
    await expect(getSession({ clients }, clientPrincipal)).rejects.toThrow('tenant');
  });
});
