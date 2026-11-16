// Fixtures shared by the unit tests of the client login use cases. Imported by tests only.
import type { Principal } from '@/shared/kernel';
import { createFakeClientUsers, type FakeClientUsers } from './fake-client-users';

export const CLIENT_A = '00000000-0000-4000-8000-00000000000a';
export const CLIENT_B = '00000000-0000-4000-8000-00000000000b';
export const UNKNOWN_CLIENT = '00000000-0000-4000-8000-0000000000ff';

export const CEO_ID = '11111111-1111-4111-8111-111111111111';
export const USER_A1 = '00000000-0000-4000-8000-0000000000a1';
export const USER_B1 = '00000000-0000-4000-8000-0000000000b1';

export const ceoPrincipal: Principal = {
  userId: CEO_ID,
  role: 'ceo',
  clientId: null,
  displayName: 'CEO',
  aal: 'aal2',
  pendingActions: [],
};

export const clientPrincipal: Principal = {
  userId: USER_A1,
  role: 'client',
  clientId: CLIENT_A,
  displayName: 'Cliente',
  aal: 'aal1',
  pendingActions: [],
};

/**
 * A stand-in for the generated password, built at run time (a literal that looks like a secret would
 * trip the secret scanners): 20 characters, low entropy, never a real credential.
 */
export const fakePassword = (label: string): string => `${label}`.padEnd(20, 'x').slice(0, 20);

/** Two clients (A active, B active) with one login each, plus a CEO account that is not a login. */
export function worldWithTwoClients(): FakeClientUsers {
  const world = createFakeClientUsers([
    { id: CLIENT_A, name: 'Cliente A', archived: false },
    { id: CLIENT_B, name: 'Cliente B', archived: false },
  ]);
  world.seed({ id: USER_A1, clientId: CLIENT_A, email: 'a1@cliente.test', displayName: 'A1' });
  world.seed({ id: USER_B1, clientId: CLIENT_B, email: 'b1@cliente.test', displayName: 'B1' });
  world.seed({
    id: CEO_ID,
    role: 'ceo',
    clientId: null,
    email: 'ceo@empresa.test',
    displayName: 'CEO',
  });
  return world;
}
