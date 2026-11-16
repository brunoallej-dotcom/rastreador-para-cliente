import { describe, expect, it } from 'vitest';
import { ForbiddenError, NotFoundError, ServiceUnavailableError } from '@/shared/kernel';
import { ClientUserResetIncompleteError } from '../domain/client-user-errors';
import {
  CEO_ID,
  CLIENT_A,
  USER_A1,
  USER_B1,
  ceoPrincipal,
  clientPrincipal,
  fakePassword,
  worldWithTwoClients,
} from './client-user-fixtures';
import { resetClientUserPassword } from './reset-client-user-password';

const PASSWORD = fakePassword('Reset');
const INPUT = { clientId: CLIENT_A, userId: USER_A1 };

const deps = (world: ReturnType<typeof worldWithTwoClients>) => ({
  users: world.users,
  accounts: world.accounts,
  generatePassword: () => PASSWORD,
});

describe('resetClientUserPassword', () => {
  it('AC-14: stores a new password, requires a change, renews the baseline and revokes the sessions', async () => {
    const world = worldWithTwoClients();
    const before = world.records.get(USER_A1)?.password;

    const result = await resetClientUserPassword(deps(world), ceoPrincipal, INPUT);

    expect(result).toEqual({ ok: true, value: { temporaryPassword: PASSWORD } });
    expect(world.records.get(USER_A1)).toMatchObject({
      password: PASSWORD,
      mustChangePassword: true,
      sessions: 0,
      passwordBaselines: 1,
    });
    expect(world.records.get(USER_A1)?.password).not.toBe(before);
  });

  it('F-41: every reset renews the baseline (the 72 h start again)', async () => {
    const world = worldWithTwoClients();

    await resetClientUserPassword(deps(world), ceoPrincipal, INPUT);
    await resetClientUserPassword(deps(world), ceoPrincipal, INPUT);

    expect(world.records.get(USER_A1)?.passwordBaselines).toBe(2);
  });

  it('AC-14: the password is stored in the Auth server BEFORE the database step (spec §3.4)', async () => {
    const world = worldWithTwoClients();

    await resetClientUserPassword(deps(world), ceoPrincipal, INPUT);

    const writes = world.calls.filter(
      (call) => call === 'setPassword' || call === 'requirePasswordChange',
    );
    expect(writes).toEqual(['setPassword', 'requirePasswordChange']);
  });

  it('AC-14: uses the platform generator by default: 20 characters', async () => {
    const world = worldWithTwoClients();

    const result = await resetClientUserPassword(
      { users: world.users, accounts: world.accounts },
      ceoPrincipal,
      INPUT,
    );

    expect(result.ok && result.value.temporaryPassword).toHaveLength(20);
  });

  it('E-19: a user of another client is 404 and no password is touched', async () => {
    const world = worldWithTwoClients();
    const before = world.records.get(USER_B1)?.password;

    const result = await resetClientUserPassword(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: USER_B1,
    });

    expect(!result.ok && result.error).toBeInstanceOf(NotFoundError);
    expect(world.calls).not.toContain('setPassword');
    expect(world.records.get(USER_B1)?.password).toBe(before);
  });

  it('E-19: a CEO is never reset through this route: 404', async () => {
    const world = worldWithTwoClients();

    const result = await resetClientUserPassword(deps(world), ceoPrincipal, {
      clientId: CLIENT_A,
      userId: CEO_ID,
    });

    expect(!result.ok && result.error).toBeInstanceOf(NotFoundError);
    expect(world.calls).not.toContain('setPassword');
  });

  it('the Auth call fails: nothing is marked, the answer is 503 and no password is returned', async () => {
    const world = worldWithTwoClients();
    world.failNext('setPassword');

    await expect(resetClientUserPassword(deps(world), ceoPrincipal, INPUT)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );

    expect(world.calls).not.toContain('requirePasswordChange');
    expect(world.records.get(USER_A1)).toMatchObject({ mustChangePassword: false, sessions: 1 });
  });

  it('the database step fails once: it is tried again and the reset completes', async () => {
    const world = worldWithTwoClients();
    world.failNext('requirePasswordChange');

    const result = await resetClientUserPassword(deps(world), ceoPrincipal, INPUT);

    expect(result.ok).toBe(true);
    expect(world.calls.filter((call) => call === 'requirePasswordChange')).toHaveLength(2);
    expect(world.records.get(USER_A1)).toMatchObject({ mustChangePassword: true, sessions: 0 });
  });

  it('the database step keeps failing: ClientUserResetIncompleteError, and the password is NOT returned', async () => {
    const world = worldWithTwoClients();
    world.failNext('requirePasswordChange', 2);

    const attempt = resetClientUserPassword(deps(world), ceoPrincipal, INPUT);

    await expect(attempt).rejects.toBeInstanceOf(ClientUserResetIncompleteError);
    // what the error says is the documented state: the old password is gone and so are the sessions
    // (the Auth server drops them), but the database side (pending action, baseline) is not recorded
    expect(world.records.get(USER_A1)).toMatchObject({
      password: PASSWORD,
      mustChangePassword: false,
      sessions: 0,
      passwordBaselines: 0,
    });
  });

  it('the database step whose answer was lost and is then repeated finishes without harm', async () => {
    const world = worldWithTwoClients();
    world.loseAnswerOf('requirePasswordChange');

    const result = await resetClientUserPassword(deps(world), ceoPrincipal, INPUT);

    expect(result.ok).toBe(true);
    expect(world.records.get(USER_A1)).toMatchObject({ mustChangePassword: true, sessions: 0 });
  });

  it('the repeat after an incomplete reset finishes the job with another password', async () => {
    const world = worldWithTwoClients();
    world.failNext('requirePasswordChange', 2);
    await resetClientUserPassword(deps(world), ceoPrincipal, INPUT).catch(() => undefined);

    const repeated = await resetClientUserPassword(
      { ...deps(world), generatePassword: () => fakePassword('Second') },
      ceoPrincipal,
      INPUT,
    );

    expect(repeated.ok && repeated.value.temporaryPassword).toBe(fakePassword('Second'));
    expect(world.records.get(USER_A1)).toMatchObject({ mustChangePassword: true, sessions: 0 });
  });

  it('SEC-04: a client user is refused before anything is read', async () => {
    const world = worldWithTwoClients();

    const result = await resetClientUserPassword(deps(world), clientPrincipal, INPUT);

    expect(!result.ok && result.error).toBeInstanceOf(ForbiddenError);
    expect(world.calls).toEqual([]);
  });
});
