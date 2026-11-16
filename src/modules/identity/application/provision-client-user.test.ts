import { describe, expect, it } from 'vitest';
import { ForbiddenError, NotFoundError, ServiceUnavailableError } from '@/shared/kernel';
import {
  ClientArchivedError,
  ClientUserProvisionOrphanedError,
  ClientUserProvisionRolledBackError,
  EmailAlreadyRegisteredError,
  UserLimitReachedError,
} from '../domain/client-user-errors';
import {
  CLIENT_A,
  UNKNOWN_CLIENT,
  ceoPrincipal,
  clientPrincipal,
  fakePassword,
  worldWithTwoClients,
} from './client-user-fixtures';
import { provisionClientUser } from './provision-client-user';

const INPUT = { clientId: CLIENT_A, email: 'novo@cliente.test', displayName: 'Maria Souza' };
const PASSWORD = fakePassword('Provision');

const deps = (world: ReturnType<typeof worldWithTwoClients>) => ({
  clients: world.clients,
  users: world.users,
  accounts: world.accounts,
  generatePassword: () => PASSWORD,
});

describe('provisionClientUser', () => {
  it('AC-12: creates the login with the temporary password, born with CHANGE_PASSWORD, and returns it once', async () => {
    const world = worldWithTwoClients();

    const result = await provisionClientUser(deps(world), ceoPrincipal, INPUT);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.temporaryPassword).toBe(PASSWORD);
    expect(result.value.user).toMatchObject({
      email: INPUT.email,
      displayName: INPUT.displayName,
      disabled: false,
      mustChangePassword: true,
      lastSignInAt: null,
    });
    const record = world.records.get(result.value.user.id);
    // the password is stored in the Auth server in the SAME call that creates the account (ADR 0007)
    expect(record).toMatchObject({ password: PASSWORD, provisioned: true, clientId: CLIENT_A });
  });

  it('AC-12: uses the platform generator by default: 20 characters', async () => {
    const world = worldWithTwoClients();

    const result = await provisionClientUser(
      { clients: world.clients, users: world.users, accounts: world.accounts },
      ceoPrincipal,
      INPUT,
    );

    expect(result.ok && result.value.temporaryPassword).toHaveLength(20);
  });

  it('SEC-03: the tenant of the new login is the clientId of the call, nothing else', async () => {
    const world = worldWithTwoClients();

    const result = await provisionClientUser(deps(world), ceoPrincipal, INPUT);

    expect(result.ok && world.records.get(result.value.user.id)?.clientId).toBe(CLIENT_A);
  });

  it('E-17: an e-mail that already has an account is EMAIL_ALREADY_REGISTERED and nothing else is called', async () => {
    const world = worldWithTwoClients();

    const result = await provisionClientUser(deps(world), ceoPrincipal, {
      ...INPUT,
      email: 'b1@cliente.test',
    });

    expect(!result.ok && result.error).toBeInstanceOf(EmailAlreadyRegisteredError);
    expect(world.calls).not.toContain('recordProvisioned');
    expect(world.accountsOf(CLIENT_A)).toHaveLength(1);
  });

  it('E-17: the address of a CEO is taken too, whatever the client', async () => {
    const world = worldWithTwoClients();

    const result = await provisionClientUser(deps(world), ceoPrincipal, {
      ...INPUT,
      email: 'ceo@empresa.test',
    });

    expect(!result.ok && result.error).toBeInstanceOf(EmailAlreadyRegisteredError);
  });

  it('E-16: an archived client is CLIENT_ARCHIVED and no account is created', async () => {
    const world = worldWithTwoClients();
    world.clientRows.set(CLIENT_A, { name: 'Cliente A', archived: true });

    const result = await provisionClientUser(deps(world), ceoPrincipal, INPUT);

    expect(!result.ok && result.error).toBeInstanceOf(ClientArchivedError);
    expect(world.calls).not.toContain('createClientUser');
  });

  it('E-16: a client archived between the check and the creation is still CLIENT_ARCHIVED (the trigger decides, the use case explains)', async () => {
    const world = worldWithTwoClients();
    world.beforeCreate = () =>
      world.clientRows.set(CLIENT_A, { name: 'Cliente A', archived: true });

    const result = await provisionClientUser(deps(world), ceoPrincipal, INPUT);

    expect(!result.ok && result.error).toBeInstanceOf(ClientArchivedError);
    expect(world.accountsOf(CLIENT_A)).toHaveLength(1);
  });

  it('E-16: a client that does not exist is 404', async () => {
    const world = worldWithTwoClients();

    const result = await provisionClientUser(deps(world), ceoPrincipal, {
      ...INPUT,
      clientId: UNKNOWN_CLIENT,
    });

    expect(!result.ok && result.error).toBeInstanceOf(NotFoundError);
  });

  it('E-18: a client with 10 logins is USER_LIMIT_REACHED, disabled ones counted, and nothing is created', async () => {
    const world = worldWithTwoClients();
    for (let index = 0; index < 9; index += 1) {
      world.seed({
        id: `00000000-0000-4000-8000-0000000001${String(index).padStart(2, '0')}`,
        clientId: CLIENT_A,
        email: `extra${index}@cliente.test`,
        disabled: index % 2 === 0,
      });
    }
    expect(world.accountsOf(CLIENT_A)).toHaveLength(10);

    const result = await provisionClientUser(deps(world), ceoPrincipal, INPUT);

    expect(!result.ok && result.error).toBeInstanceOf(UserLimitReachedError);
    expect(world.calls).not.toContain('createClientUser');
  });

  it('E-18: the tenth login is accepted, the eleventh refused', async () => {
    const world = worldWithTwoClients();
    for (let index = 0; index < 8; index += 1) {
      world.seed({
        id: `00000000-0000-4000-8000-0000000002${String(index).padStart(2, '0')}`,
        clientId: CLIENT_A,
        email: `fill${index}@cliente.test`,
      });
    }

    const tenth = await provisionClientUser(deps(world), ceoPrincipal, INPUT);
    const eleventh = await provisionClientUser(deps(world), ceoPrincipal, {
      ...INPUT,
      email: 'outro@cliente.test',
    });

    expect(tenth.ok).toBe(true);
    expect(!eleventh.ok && eleventh.error).toBeInstanceOf(UserLimitReachedError);
  });

  it('E-18: a client filled by a concurrent request after the check is USER_LIMIT_REACHED, not a 503', async () => {
    const world = worldWithTwoClients();
    for (let index = 0; index < 8; index += 1) {
      world.seed({
        id: `00000000-0000-4000-8000-0000000003${String(index).padStart(2, '0')}`,
        clientId: CLIENT_A,
        email: `race${index}@cliente.test`,
      });
    }
    world.beforeCreate = () =>
      world.seed({
        id: '00000000-0000-4000-8000-0000000003ff',
        clientId: CLIENT_A,
        email: 'winner@cliente.test',
      });

    const result = await provisionClientUser(deps(world), ceoPrincipal, INPUT);

    expect(!result.ok && result.error).toBeInstanceOf(UserLimitReachedError);
  });

  it('E-21: an outage of the Auth server with no refusal behind it stays a 503', async () => {
    const world = worldWithTwoClients();
    world.failNext('createClientUser');

    await expect(provisionClientUser(deps(world), ceoPrincipal, INPUT)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
    expect(world.accountsOf(CLIENT_A)).toHaveLength(1);
  });

  it('E-21: if the look behind a failed creation fails too, the original failure stands', async () => {
    const world = worldWithTwoClients();
    world.failNext('createClientUser');
    // the first `status` is the check before the creation; the second is the look behind
    let lookups = 0;
    const clients = {
      status: (clientId: string) => {
        lookups += 1;
        return lookups === 1
          ? world.clients.status(clientId)
          : Promise.reject(new ServiceUnavailableError('status unavailable'));
      },
    };

    await expect(
      provisionClientUser({ ...deps(world), clients }, ceoPrincipal, INPUT),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
    expect(lookups).toBe(2);
  });

  it('E-23: the audit record fails after createUser: the account is deleted, the answer is a 503 and no password is returned', async () => {
    const world = worldWithTwoClients();
    world.failNext('recordProvisioned');

    const attempt = provisionClientUser(deps(world), ceoPrincipal, INPUT);

    await expect(attempt).rejects.toBeInstanceOf(ClientUserProvisionRolledBackError);
    expect(world.calls).toContain('deleteUser');
    expect(world.accountsOf(CLIENT_A)).toHaveLength(1);
    expect([...world.records.values()].some((record) => record.email === INPUT.email)).toBe(false);
  });

  it('E-23: the record whose answer was lost is compensated all the same (the account is deleted)', async () => {
    const world = worldWithTwoClients();
    world.loseAnswerOf('recordProvisioned');

    await expect(provisionClientUser(deps(world), ceoPrincipal, INPUT)).rejects.toBeInstanceOf(
      ClientUserProvisionRolledBackError,
    );
    expect([...world.records.values()].some((record) => record.email === INPUT.email)).toBe(false);
  });

  it('E-23: the read-back after the record fails: the account is deleted too (the password is never released on a half-made login)', async () => {
    const world = worldWithTwoClients();
    // the checks before the creation use `list` once; the read-back is the next one
    world.beforeCreate = () => world.failNext('list');

    await expect(provisionClientUser(deps(world), ceoPrincipal, INPUT)).rejects.toBeInstanceOf(
      ClientUserProvisionRolledBackError,
    );
    expect([...world.records.values()].some((record) => record.email === INPUT.email)).toBe(false);
  });

  it('E-23: the first deletion fails and the second works: still rolled back, nothing is left', async () => {
    const world = worldWithTwoClients();
    world.failNext('recordProvisioned');
    world.failNext('deleteUser', 1);

    await expect(provisionClientUser(deps(world), ceoPrincipal, INPUT)).rejects.toBeInstanceOf(
      ClientUserProvisionRolledBackError,
    );
    expect(world.calls.filter((call) => call === 'deleteUser')).toHaveLength(2);
    expect([...world.records.values()].some((record) => record.email === INPUT.email)).toBe(false);
  });

  it('E-23: if the deletion fails too, the orphan error carries the id of the account left behind', async () => {
    const world = worldWithTwoClients();
    world.failNext('recordProvisioned');
    world.failNext('deleteUser', 2);

    const attempt = provisionClientUser(deps(world), ceoPrincipal, INPUT);

    const error: unknown = await attempt.catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ClientUserProvisionOrphanedError);
    const orphan = [...world.records.values()].find((record) => record.email === INPUT.email);
    expect(orphan).toBeDefined();
    expect((error as ClientUserProvisionOrphanedError).userId).toBe(orphan?.id);
    expect((error as ClientUserProvisionOrphanedError).detail).not.toContain(INPUT.email);
  });

  it('SEC-04: a database that no longer sees a CEO refuses the record: the account is deleted and the answer is 403', async () => {
    const world = worldWithTwoClients();
    // the CEO's authority ends between the creation and the record
    const users = {
      ...world.users,
      recordProvisioned: () =>
        Promise.resolve({ ok: false as const, error: new ForbiddenError('denied') }),
    };

    const result = await provisionClientUser({ ...deps(world), users }, ceoPrincipal, INPUT);

    expect(!result.ok && result.error).toBeInstanceOf(ForbiddenError);
    expect([...world.records.values()].some((record) => record.email === INPUT.email)).toBe(false);
  });

  it('SEC-04: a client user is refused before anything is read', async () => {
    const world = worldWithTwoClients();

    const result = await provisionClientUser(deps(world), clientPrincipal, INPUT);

    expect(!result.ok && result.error).toBeInstanceOf(ForbiddenError);
    expect(world.calls).toEqual([]);
  });

  it('SEC-16: the temporary password is only in the success value: no error carries it', async () => {
    const world = worldWithTwoClients();
    world.failNext('recordProvisioned');

    const error: unknown = await provisionClientUser(deps(world), ceoPrincipal, INPUT).catch(
      (caught: unknown) => caught,
    );

    expect(
      JSON.stringify({
        message: String((error as Error).message),
        detail: (error as { detail?: string }).detail,
      }),
    ).not.toContain(PASSWORD);
  });
});
