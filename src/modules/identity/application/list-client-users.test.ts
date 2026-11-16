import { describe, expect, it } from 'vitest';
import { ForbiddenError, NotFoundError } from '@/shared/kernel';
import {
  CEO_ID,
  CLIENT_A,
  UNKNOWN_CLIENT,
  USER_A1,
  ceoPrincipal,
  clientPrincipal,
  worldWithTwoClients,
} from './client-user-fixtures';
import { listClientUsers } from './list-client-users';

describe('listClientUsers', () => {
  it('RF-07: lists the logins of the client of the path, and only those', async () => {
    const world = worldWithTwoClients();

    const result = await listClientUsers({ users: world.users }, ceoPrincipal, {
      clientId: CLIENT_A,
    });

    expect(result.ok && result.value.map((user) => user.id)).toEqual([USER_A1]);
  });

  it('E-19: a CEO account is never in the list', async () => {
    const world = worldWithTwoClients();

    const result = await listClientUsers({ users: world.users }, ceoPrincipal, {
      clientId: CLIENT_A,
    });

    expect(result.ok && result.value.some((user) => user.id === CEO_ID)).toBe(false);
  });

  it('a client that does not exist is 404', async () => {
    const world = worldWithTwoClients();

    const result = await listClientUsers({ users: world.users }, ceoPrincipal, {
      clientId: UNKNOWN_CLIENT,
    });

    expect(!result.ok && result.error).toBeInstanceOf(NotFoundError);
  });

  it('SEC-04: a client user is refused and the repository is never asked', async () => {
    const world = worldWithTwoClients();

    const result = await listClientUsers({ users: world.users }, clientPrincipal, {
      clientId: CLIENT_A,
    });

    expect(!result.ok && result.error).toBeInstanceOf(ForbiddenError);
    expect(world.calls).toEqual([]);
  });
});
