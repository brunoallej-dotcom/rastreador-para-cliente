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
import type { ClientUserNotice } from '../domain/client-user-ports';
import { UnexpectedAuthAnswerError } from '../domain/errors';
import { updateClientUser } from './update-client-user';

const deps = (world: ReturnType<typeof worldWithTwoClients>, notices: ClientUserNotice[] = []) => ({
  users: world.users,
  accounts: world.accounts,
  report: (notice: ClientUserNotice) => void notices.push(notice),
});

describe('updateClientUser', () => {
  it('AC-13: disabling blocks the login in the database (sessions gone) and bans it in the Auth server', async () => {
    const world = worldWithTwoClients();
    const notices: ClientUserNotice[] = [];

    const result = await updateClientUser(deps(world, notices), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });

    expect(result.ok && result.value).toMatchObject({ id: USER_A1, disabled: true });
    expect(world.records.get(USER_A1)).toMatchObject({ disabled: true, banned: true, sessions: 0 });
    expect(notices).toEqual([]);
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

    expect(result.ok && result.value.disabled).toBe(false);
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

  it('E-24: a ban that fails after the database disabled the login is still a success, reported with the reason', async () => {
    const world = worldWithTwoClients();
    world.failNext('setBanned');
    const notices: ClientUserNotice[] = [];

    const result = await updateClientUser(deps(world, notices), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });

    expect(result.ok && result.value).toMatchObject({ disabled: true });
    expect(world.records.get(USER_A1)).toMatchObject({
      disabled: true,
      banned: false,
      sessions: 0,
    });
    expect(notices).toEqual([{ kind: 'ban_failed', reason: 'unavailable' }]);
  });

  it('F-94: an unexpected Auth answer to the ban is still a 200 (the database decides) and is reported as `unexpected`', async () => {
    const world = worldWithTwoClients();
    world.failNext(
      'setBanned',
      1,
      new UnexpectedAuthAnswerError('ban the login', { status: 422, code: 'weak_password' }),
    );
    const notices: ClientUserNotice[] = [];

    const result = await updateClientUser(deps(world, notices), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });

    expect(result.ok && result.value.disabled).toBe(true);
    expect(notices).toEqual([{ kind: 'ban_failed', reason: 'unexpected' }]);
  });

  it('F-94: an Auth server that does not have the user is reported as `not_found`, also a 200', async () => {
    const world = worldWithTwoClients();
    const accounts = {
      ...world.accounts,
      setBanned: () => Promise.resolve({ ok: false as const, error: new NotFoundError('gone') }),
    };
    const notices: ClientUserNotice[] = [];

    const result = await updateClientUser({ ...deps(world, notices), accounts }, ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });

    expect(result.ok && result.value.disabled).toBe(true);
    expect(notices).toEqual([{ kind: 'ban_failed', reason: 'not_found' }]);
  });

  it('F-94: only the three classified failures are swallowed: a bug (an unclassified error) is thrown, after the database disabled the login', async () => {
    const world = worldWithTwoClients();
    world.failNext('setBanned', 1, new TypeError('a bug'));

    await expect(
      updateClientUser(deps(world), ceoPrincipal, {
        clientId: CLIENT_A,
        userId: USER_A1,
        disabled: true,
      }),
    ).rejects.toBeInstanceOf(TypeError);

    expect(world.records.get(USER_A1)?.disabled).toBe(true);
  });

  it('E-24: repeating the disable tries the ban again (the whole update is idempotent)', async () => {
    const world = worldWithTwoClients();
    world.failNext('setBanned');
    await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });

    const notices: ClientUserNotice[] = [];

    const again = await updateClientUser(deps(world, notices), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });

    expect(again.ok).toBe(true);
    expect(notices).toEqual([]);
    expect(world.records.get(USER_A1)?.banned).toBe(true);
    // the login was already disabled in the database: no second event, and the ban was still tried
    expect(world.records.get(USER_A1)?.audit).toEqual(['account.disabled']);
  });

  it('E-56: the database step of a re-enable fails after the unban: the ban is put back, the login stays blocked in both places, and it is reported', async () => {
    const world = worldWithTwoClients();
    await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });
    world.failNext('setDisabled');
    const notices: ClientUserNotice[] = [];

    await expect(
      updateClientUser(deps(world, notices), ceoPrincipal, {
        clientId: CLIENT_A,
        userId: USER_A1,
        disabled: false,
      }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);

    expect(world.records.get(USER_A1)).toMatchObject({ disabled: true, banned: true });
    expect(notices).toEqual([{ kind: 'reban_after_failed_enable', rebanned: true }]);
  });

  it('E-56: the same when the database refuses the re-enable (an answer, not a throw)', async () => {
    const world = worldWithTwoClients();
    await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });
    world.refuseNext('setDisabled', new ForbiddenError('denied'));
    const notices: ClientUserNotice[] = [];

    const result = await updateClientUser(deps(world, notices), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: false,
    });

    expect(!result.ok && result.error).toBeInstanceOf(ForbiddenError);
    expect(world.records.get(USER_A1)).toMatchObject({ disabled: true, banned: true });
    expect(notices).toEqual([{ kind: 'reban_after_failed_enable', rebanned: true }]);
  });

  it('E-56: if the ban cannot be put back either, that is reported with the reason, and the first failure is still the answer', async () => {
    const world = worldWithTwoClients();
    await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });
    world.failNext('setDisabled');
    const notices: ClientUserNotice[] = [];
    // the unban (the first setBanned of the re-enable) works, the ban that follows does not
    let bans = 0;
    const accounts = {
      ...world.accounts,
      setBanned: (userId: string, banned: boolean) => {
        bans += 1;
        return bans === 1
          ? world.accounts.setBanned(userId, banned)
          : Promise.reject(new ServiceUnavailableError('ban unavailable'));
      },
    };

    await expect(
      updateClientUser({ ...deps(world, notices), accounts }, ceoPrincipal, {
        clientId: CLIENT_A,
        userId: USER_A1,
        disabled: false,
      }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);

    expect(notices).toEqual([
      { kind: 'reban_after_failed_enable', rebanned: false, reason: 'unavailable' },
    ]);
  });

  it('M2: enabling a login that is already enabled touches nothing: no unban, no database call, and no re-ban to lock it out when something fails', async () => {
    const world = worldWithTwoClients();
    // were the step not skipped, this failure would put a ban on an ACTIVE login
    world.failNext('setDisabled');
    const notices: ClientUserNotice[] = [];

    const result = await updateClientUser(deps(world, notices), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: false,
    });

    expect(result.ok && result.value.disabled).toBe(false);
    expect(world.calls).not.toContain('setBanned');
    expect(world.calls).not.toContain('setDisabled');
    expect(world.records.get(USER_A1)?.banned).toBe(false);
    expect(notices).toEqual([]);
  });

  it('M2: a repeated enable whose database step would fail never bans an active login (the first enable worked, the second is the no-op)', async () => {
    const world = worldWithTwoClients();
    await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: true,
    });
    await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: false,
    });
    world.failNext('setDisabled');

    const again = await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      disabled: false,
    });

    expect(again.ok).toBe(true);
    expect(world.records.get(USER_A1)).toMatchObject({ disabled: false, banned: false });
  });

  it('F-92a: a login enabled in the database but banned in Auth (the worst interleaving) is not touched by a bare enable, and a disable followed by an enable repairs it', async () => {
    const world = worldWithTwoClients();
    const record = world.records.get(USER_A1);
    if (record !== undefined) record.banned = true;
    const run = (disabled: boolean) =>
      updateClientUser(deps(world), ceoPrincipal, {
        clientId: CLIENT_A,
        userId: USER_A1,
        disabled,
      });

    await run(false);
    expect(world.records.get(USER_A1)?.banned).toBe(true);

    await run(true);
    await run(false);

    expect(world.records.get(USER_A1)).toMatchObject({ disabled: false, banned: false });
  });

  it('no-op: a rename to the name the login already has writes nothing and no second account.updated', async () => {
    const world = worldWithTwoClients();
    const name = world.records.get(USER_A1)?.displayName ?? '';

    const result = await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      displayName: name,
    });

    expect(result.ok && result.value.displayName).toBe(name);
    expect(world.calls).not.toContain('setDisplayName');
    expect(world.records.get(USER_A1)?.audit).toEqual([]);
  });

  it('a rename to another name is audited once, and repeating the same rename writes nothing', async () => {
    const world = worldWithTwoClients();

    await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      displayName: 'Outro Nome',
    });
    await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      displayName: 'Outro Nome',
    });

    expect(world.records.get(USER_A1)?.audit).toEqual(['account.updated']);
  });

  it('disabling and enabling twice audits each change once (the database function is the deduplicator)', async () => {
    const world = worldWithTwoClients();
    const run = (disabled: boolean) =>
      updateClientUser(deps(world), ceoPrincipal, {
        clientId: CLIENT_A,
        userId: USER_A1,
        disabled,
      });

    await run(true);
    await run(true);
    await run(false);
    await run(false);

    expect(world.records.get(USER_A1)?.audit).toEqual(['account.disabled', 'account.enabled']);
  });

  it('AC-13: renames a login, and a rename and a disable in one request both apply', async () => {
    const world = worldWithTwoClients();

    const result = await updateClientUser(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_A1,
      displayName: 'Novo Nome',
      disabled: true,
    });

    expect(result.ok && result.value).toMatchObject({
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
