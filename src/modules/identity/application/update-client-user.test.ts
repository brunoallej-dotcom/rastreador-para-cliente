import { describe, expect, it } from 'vitest';
import {
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  ValidationError,
} from '@/shared/kernel';
import {
  CEO_ID,
  CLIENT_A,
  CLIENT_B,
  UNKNOWN_CLIENT,
  USER_A1,
  USER_B1,
  ceoPrincipal,
  clientPrincipal,
  worldWithTwoClients,
} from './client-user-fixtures';
import { updateClientUser } from './update-client-user';

const deps = (world: ReturnType<typeof worldWithTwoClients>) => ({
  users: world.users,
  accounts: world.accounts,
});

describe('updateClientUser', () => {
  it('AC-13: disabling blocks the login in the database (sessions gone) and bans it in the Auth server', async () => {
    const world = worldWithTwoClients();

    const result = await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });

    expect(result.ok && result.value).toMatchObject({
      banSynced: true,
      user: { id: USER_A1, disabled: true },
    });
    expect(world.records.get(USER_A1)).toMatchObject({ disabled: true, banned: true, sessions: 0 });
  });

  it('AC-13: disabling writes the database BEFORE the ban (the block that counts comes first)', async () => {
    const world = worldWithTwoClients();

    await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });

    const writes = world.calls.filter((call) => call === 'setDisabled' || call === 'setBanned');
    expect(writes).toEqual(['setDisabled', 'setBanned']);
  });

  it('AC-13: re-enabling lifts the ban FIRST and then the database flag', async () => {
    const world = worldWithTwoClients();
    await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });
    world.calls.length = 0;

    const result = await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: false,
    });

    expect(result.ok && result.value.user.disabled).toBe(false);
    expect(world.records.get(USER_A1)).toMatchObject({ disabled: false, banned: false });
    const writes = world.calls.filter((call) => call === 'setDisabled' || call === 'setBanned');
    expect(writes).toEqual(['setBanned', 'setDisabled']);
  });

  it('AC-13: an unban that fails leaves the login disabled in the database (503, nothing enabled)', async () => {
    const world = worldWithTwoClients();
    await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });
    world.failNext('setBanned');

    await expect(
      updateClientUser(deps(world), ceoPrincipal, {
        clientId: CLIENT_A,
        userId: USER_A1,
        disabled: false,
      }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);

    expect(world.records.get(USER_A1)?.disabled).toBe(true);
  });

  it('E-24: a ban that fails after the database disabled the login is still a success, flagged for the log', async () => {
    const world = worldWithTwoClients();
    world.failNext('setBanned');

    const result = await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });

    expect(result.ok && result.value).toMatchObject({
      banSynced: false,
      user: { disabled: true },
    });
    expect(world.records.get(USER_A1)).toMatchObject({
      disabled: true,
      banned: false,
      sessions: 0,
    });
  });

  it('E-24: repeating the disable tries the ban again (the whole update is idempotent)', async () => {
    const world = worldWithTwoClients();
    world.failNext('setBanned');
    await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });

    const again = await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });

    expect(again.ok && again.value.banSynced).toBe(true);
    expect(world.records.get(USER_A1)?.banned).toBe(true);
  });

  it('AC-13: renames a login, and a rename and a disable in one request both apply', async () => {
    const world = worldWithTwoClients();

    const result = await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      displayName: 'Novo Nome',
      disabled: true,
    });

    expect(result.ok && result.value.user).toMatchObject({
      displayName: 'Novo Nome',
      disabled: true,
    });
  });

  it('a rename that fails touches nothing else (the rename goes first)', async () => {
    const world = worldWithTwoClients();
    world.failNext('setDisplayName');

    await expect(
      updateClientUser(deps(world), ceoPrincipal, {
        clientId: CLIENT_A,
        userId: USER_A1,
        displayName: 'Novo',
        disabled: true,
      }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);

    expect(world.records.get(USER_A1)).toMatchObject({ disabled: false, banned: false });
  });

  it('E-19: a user of another client is 404 and nothing is written', async () => {
    const world = worldWithTwoClients();

    const result = await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_B1,
      disabled: true,
    });

    expect(!result.ok && result.error).toBeInstanceOf(NotFoundError);
    expect(world.records.get(USER_B1)).toMatchObject({ disabled: false, banned: false });
    expect(world.calls).not.toContain('setDisabled');
    expect(world.calls).not.toContain('setBanned');
  });

  it('E-19: a CEO is never a login: 404, whatever the client', async () => {
    const world = worldWithTwoClients();

    const result = await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: CEO_ID,
      disabled: true,
    });

    expect(!result.ok && result.error).toBeInstanceOf(NotFoundError);
    expect(world.records.get(CEO_ID)?.disabled).toBe(false);
  });

  it('E-19: a user that does not exist, a user of another client and an unknown client look the same', async () => {
    const world = worldWithTwoClients();
    const body = (clientId: string, userId: string) =>
      updateClientUser(deps(world), ceoPrincipal, { clientId, userId, disabled: true }).then(
        (result) =>
          result.ok ? undefined : { code: result.error.code, detail: result.error.detail },
      );

    const crossTenant = await body(CLIENT_A, USER_B1);
    const missingUser = await body(CLIENT_A, '00000000-0000-4000-8000-0000000000dd');
    const missingClient = await body(UNKNOWN_CLIENT, USER_A1);

    expect(crossTenant).toEqual({ code: 'NOT_FOUND', detail: 'Client login not found.' });
    expect(missingUser).toEqual(crossTenant);
    expect(missingClient).toEqual(crossTenant);
  });

  it('a request that names nothing to change is a 400 and reads nothing', async () => {
    const world = worldWithTwoClients();

    const result = await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
    });

    expect(!result.ok && result.error).toBeInstanceOf(ValidationError);
    expect(world.calls).toEqual([]);
  });

  it('SEC-04: a client user is refused before anything is read', async () => {
    const world = worldWithTwoClients();

    const result = await updateClientUser(deps(world), clientPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });

    expect(!result.ok && result.error).toBeInstanceOf(ForbiddenError);
    expect(world.calls).toEqual([]);
  });

  it('a user the client of the path does not have, in a client with logins, never reaches the Auth server', async () => {
    const world = worldWithTwoClients();

    await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_B,
      userId: USER_A1,
      disabled: false,
    });

    expect(world.calls).not.toContain('setBanned');
  });
});
