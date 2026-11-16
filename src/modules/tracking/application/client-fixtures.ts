// Fixtures shared by the unit tests of the client use cases. Imported by tests only.
import type { Principal } from '@/shared/kernel';
import type { Client } from '../domain/client';

export const ceoPrincipal: Principal = {
  userId: '11111111-1111-4111-8111-111111111111',
  role: 'ceo',
  clientId: null,
  displayName: 'CEO',
  aal: 'aal2',
  pendingActions: [],
};

export const clientPrincipal: Principal = {
  userId: '22222222-2222-4222-8222-222222222222',
  role: 'client',
  clientId: '00000000-0000-4000-8000-00000000000a',
  displayName: 'Cliente',
  aal: 'aal1',
  pendingActions: [],
};

export function clientFixture(overrides: Partial<Client> & Pick<Client, 'id'>): Client {
  return {
    name: 'Cliente',
    archivedAt: null,
    activeProcessCount: 0,
    processCount: 0,
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    updatedAt: new Date('2026-01-01T00:00:00.000Z'),
    ...overrides,
  };
}
