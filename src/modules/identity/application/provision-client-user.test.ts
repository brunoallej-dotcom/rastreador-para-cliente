import { describe, expect, it } from 'vitest';
import {
  fixedClock,
  ForbiddenError,
  NotFoundError,
  ServiceUnavailableError,
  ValidationError,
} from '@/shared/kernel';
import {
  ClientArchivedError,
  ClientUserProvisionAnswerLostError,
  ClientUserProvisionOrphanedError,
  ClientUserProvisionRolledBackError,
  ClientUserProvisionUnconfirmedError,
  EmailAlreadyRegisteredError,
  UserLimitReachedError,
} from '../domain/client-user-errors';
import { UnexpectedAuthAnswerError } from '../domain/errors';
import {
  CLIENT_A,
  UNKNOWN_CLIENT,
  USER_A1,
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

  it('F-117: the record whose answer was lost IS on the trail: the reversal is refused (a login with account.provisioned is not a provisioning to undo), so the account is NOT deleted and stays an orphan with its record', async () => {
    const world = worldWithTwoClients();
    world.loseAnswerOf('recordProvisioned');

    const error: unknown = await provisionClientUser(deps(world), ceoPrincipal, INPUT).catch(
      (caught: unknown) => caught,
    );

    expect(error).toBeInstanceOf(ClientUserProvisionOrphanedError);
    expect(error).toBeInstanceOf(ServiceUnavailableError);
    expect(error).toMatchObject({
      reason: 'record_failed',
      deleteFailure: { kind: 'VALIDATION_ERROR' },
    });
    const orphan = [...world.records.values()].find((record) => record.email === INPUT.email);
    // the account is there, its `account.provisioned` is kept, and nothing says it was reverted
    expect(orphan).toMatchObject({ provisioned: true, mustChangePassword: true });
    expect(world.trail).toEqual([{ userId: orphan?.id, event: 'account.provisioned' }]);
    expect(world.reversals).toEqual([]);
    expect(world.calls).not.toContain('deleteUser');
    // a refusal of the database is final: the reversal was not tried a second time
    expect(world.calls.filter((call) => call === 'recordProvisionReverted')).toHaveLength(1);
  });

  it('F-93: the record answers with the login, so nothing is read after it: a list that would fail then changes nothing', async () => {
    const world = worldWithTwoClients();
    // the checks before the creation use `list` once; a read-back after the record would be the next one
    world.beforeCreate = () => world.failNext('list');

    const result = await provisionClientUser(deps(world), ceoPrincipal, INPUT);

    expect(result.ok).toBe(true);
    expect(world.calls.filter((call) => call === 'list')).toHaveLength(1);
    expect(world.calls.at(-1)).toBe('recordProvisioned');
    expect(result.ok && world.records.get(result.value.user.id)?.provisioned).toBe(true);
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

  describe('E-17: a login of the client that already has the e-mail', () => {
    it('is the 409 before anything is created, whatever its case, and it is never touched', async () => {
      const world = worldWithTwoClients();

      const result = await provisionClientUser(deps(world), ceoPrincipal, {
        ...INPUT,
        email: 'a1@cliente.test',
      });

      expect(!result.ok && result.error).toBeInstanceOf(EmailAlreadyRegisteredError);
      expect(world.calls).not.toContain('createClientUser');
      expect(world.calls).not.toContain('deleteUser');
    });
  });

  describe('F-90, E-50: a creation whose answer is lost', () => {
    const accountOf = (world: ReturnType<typeof worldWithTwoClients>) =>
      [...world.records.values()].find((record) => record.email === INPUT.email);

    it('with the login in the list: the account is taken back and the answer is a 503, never a 422', async () => {
      const world = worldWithTwoClients();
      world.loseAnswerOf('createClientUser');

      const error: unknown = await provisionClientUser(deps(world), ceoPrincipal, INPUT).catch(
        (caught: unknown) => caught,
      );

      expect(error).toBeInstanceOf(ClientUserProvisionRolledBackError);
      expect(error).toMatchObject({ reason: 'answer_lost' });
      expect(accountOf(world)).toBeUndefined();
      expect(world.calls).toContain('deleteUser');
    });

    it('with the login in the list AND the client full because of it: still a 503, since the login exists (a 422 would say "refused")', async () => {
      const world = worldWithTwoClients();
      for (let index = 0; index < 8; index += 1) {
        world.seed({
          id: `00000000-0000-4000-8000-0000000004${String(index).padStart(2, '0')}`,
          clientId: CLIENT_A,
          email: `fill${index}@cliente.test`,
        });
      }
      // the login that was just created is the 10th: the client is full now, and that is NOT a refusal
      world.loseAnswerOf('createClientUser');

      const error: unknown = await provisionClientUser(deps(world), ceoPrincipal, INPUT).catch(
        (caught: unknown) => caught,
      );

      expect(error).toBeInstanceOf(ClientUserProvisionRolledBackError);
      expect(accountOf(world)).toBeUndefined();
    });

    it('with the login in the list and the deletion failing: the orphan error carries the id and why the deletion failed, as a code and a status', async () => {
      const world = worldWithTwoClients();
      world.loseAnswerOf('createClientUser');
      world.failNext(
        'deleteUser',
        2,
        new UnexpectedAuthAnswerError('delete the login', {
          status: 500,
          code: 'unexpected_failure',
        }),
      );

      const error: unknown = await provisionClientUser(deps(world), ceoPrincipal, INPUT).catch(
        (caught: unknown) => caught,
      );

      expect(error).toBeInstanceOf(ClientUserProvisionOrphanedError);
      const orphan = accountOf(world);
      expect(error).toMatchObject({
        reason: 'answer_lost',
        userId: orphan?.id,
        deleteFailure: { status: 500, reason: 'unexpected_failure' },
      });
      expect(
        JSON.stringify((error as ClientUserProvisionOrphanedError).deleteFailure),
      ).not.toContain(INPUT.email);
    });

    it('a login with that e-mail that this request did not create is never deleted: it signed in, or it is not new', async () => {
      const world = worldWithTwoClients();
      // after the checks, somebody else's login appears with the e-mail, and the creation then fails
      const accounts = {
        ...world.accounts,
        createClientUser: () => {
          world.seed({
            id: '00000000-0000-4000-8000-0000000005aa',
            clientId: CLIENT_A,
            email: INPUT.email,
            mustChangePassword: false,
            lastSignInAt: new Date('2026-11-16T10:00:00.000Z'),
          });
          return Promise.reject(new ServiceUnavailableError('create unavailable'));
        },
      };

      await expect(
        provisionClientUser({ ...deps(world), accounts }, ceoPrincipal, INPUT),
      ).rejects.toBeInstanceOf(ServiceUnavailableError);

      expect(world.calls).not.toContain('deleteUser');
      expect(world.records.has('00000000-0000-4000-8000-0000000005aa')).toBe(true);
    });

    describe('M1: the compensation never deletes a login it cannot prove is its own', () => {
      /** The instant the attempt starts, pinned: a login is "before" or "after" it by its `createdAt`. */
      const START = new Date('2026-11-16T12:00:00.000Z');
      const at = (offsetMs: number) => new Date(START.getTime() + offsetMs);
      const RACER = '00000000-0000-4000-8000-0000000005bb';
      const RACER_TWO = '00000000-0000-4000-8000-0000000005bc';

      /**
       * Another CEO's request provisions the same e-mail in the same client right after the snapshot of
       * this one, and this one's creation then fails without an answer. `createdAts` are the instants the
       * logins that turn up were created.
       */
      async function failedCreationWithLoginsCreatedAt(createdAts: readonly Date[]) {
        const world = worldWithTwoClients();
        const ids = [RACER, RACER_TWO];
        const accounts = {
          ...world.accounts,
          createClientUser: () => {
            createdAts.forEach((createdAt, index) => {
              world.seed({
                id: ids[index] ?? RACER,
                clientId: CLIENT_A,
                email: INPUT.email,
                mustChangePassword: true,
                lastSignInAt: null,
                // a login the Auth server just created: nobody recorded `account.provisioned` yet
                provisioned: false,
                createdAt,
              });
            });
            return Promise.reject(new ServiceUnavailableError('create unavailable'));
          },
        };
        const error: unknown = await provisionClientUser(
          { ...deps(world), accounts, clock: fixedClock(START) },
          ceoPrincipal,
          INPUT,
        ).catch((caught: unknown) => caught);
        return { world, error };
      }

      it("a login created BEFORE this attempt started is another request's: nothing is deleted, the answer is 503 and the id is in the error (the old test here enshrined deleting it)", async () => {
        const { world, error } = await failedCreationWithLoginsCreatedAt([at(-10_000)]);

        expect(error).toBeInstanceOf(ClientUserProvisionAnswerLostError);
        expect((error as ClientUserProvisionAnswerLostError).userIds).toEqual([RACER]);
        expect(world.calls).not.toContain('deleteUser');
        expect(world.records.has(RACER)).toBe(true);
      });

      it("exactly one candidate created at the start of the attempt is the attempt's own: it is taken back", async () => {
        const { world, error } = await failedCreationWithLoginsCreatedAt([at(0)]);

        expect(error).toBeInstanceOf(ClientUserProvisionRolledBackError);
        expect(world.records.has(RACER)).toBe(false);
      });

      it("the clock of the database may run a little behind: 1.5 s before the start still counts as the attempt's own, 2.5 s does not", async () => {
        const within = await failedCreationWithLoginsCreatedAt([at(-1_500)]);
        const outside = await failedCreationWithLoginsCreatedAt([at(-2_500)]);

        expect(within.error).toBeInstanceOf(ClientUserProvisionRolledBackError);
        expect(outside.error).toBeInstanceOf(ClientUserProvisionAnswerLostError);
        expect(outside.world.records.has(RACER)).toBe(true);
      });

      it("TWO candidates: nobody can tell which is the attempt's, so neither is deleted and both ids are reported", async () => {
        const { world, error } = await failedCreationWithLoginsCreatedAt([at(100), at(200)]);

        expect(error).toBeInstanceOf(ClientUserProvisionAnswerLostError);
        expect((error as ClientUserProvisionAnswerLostError).userIds).toEqual([RACER, RACER_TWO]);
        expect(world.calls).not.toContain('deleteUser');
        expect(world.records.has(RACER)).toBe(true);
        expect(world.records.has(RACER_TWO)).toBe(true);
      });

      it('the error is a 503 for the client and its detail names no one', async () => {
        const { error } = await failedCreationWithLoginsCreatedAt([at(-10_000)]);

        expect(error).toBeInstanceOf(ServiceUnavailableError);
        expect(
          JSON.stringify({ detail: (error as Error & { detail?: string }).detail }),
        ).not.toContain(INPUT.email);
        expect(JSON.stringify((error as Error).message)).not.toContain(RACER);
      });
    });

    it('with the login NOT in the list and the client archived by now: 422, the trigger refused it (E-52)', async () => {
      const world = worldWithTwoClients();
      world.beforeCreate = () =>
        world.clientRows.set(CLIENT_A, { name: 'Cliente A', archived: true });

      const result = await provisionClientUser(deps(world), ceoPrincipal, INPUT);

      expect(!result.ok && result.error).toBeInstanceOf(ClientArchivedError);
    });
  });

  describe('E-55: the Auth server accepts the creation and answers without a user id', () => {
    it('the account is found by its e-mail and taken back: a 503, never a 500, and no password', async () => {
      const world = worldWithTwoClients();
      world.answerNextCreationWithoutId();

      const error: unknown = await provisionClientUser(deps(world), ceoPrincipal, INPUT).catch(
        (caught: unknown) => caught,
      );

      expect(error).toBeInstanceOf(ClientUserProvisionRolledBackError);
      expect(error).toMatchObject({ reason: 'answer_lost' });
      expect([...world.records.values()].some((record) => record.email === INPUT.email)).toBe(
        false,
      );
    });

    it('when the look for the account fails too, the unconfirmed error stands (a 503 the handler logs)', async () => {
      const world = worldWithTwoClients();
      world.answerNextCreationWithoutId();
      let lookups = 0;
      const clients = {
        status: (clientId: string) => {
          lookups += 1;
          return lookups === 1
            ? world.clients.status(clientId)
            : Promise.reject(new ServiceUnavailableError('status unavailable'));
        },
      };

      const error: unknown = await provisionClientUser(
        { ...deps(world), clients },
        ceoPrincipal,
        INPUT,
      ).catch((caught: unknown) => caught);

      expect(error).toBeInstanceOf(ClientUserProvisionUnconfirmedError);
      expect(error).toBeInstanceOf(UnexpectedAuthAnswerError);
      expect(error).toBeInstanceOf(ServiceUnavailableError);
      // the account is still there: nobody could name it
      expect([...world.records.values()].some((record) => record.email === INPUT.email)).toBe(true);
    });
  });

  describe('F-93: the reversal is on the trail BEFORE the account is deleted', () => {
    const accountOf = (world: ReturnType<typeof worldWithTwoClients>) =>
      [...world.records.values()].find((record) => record.email === INPUT.email);

    it('E-23: the order is record (fails), reversal, deletion; the trail says provision_reverted and has no provisioned', async () => {
      const world = worldWithTwoClients();
      world.failNext('recordProvisioned');

      const error: unknown = await provisionClientUser(deps(world), ceoPrincipal, INPUT).catch(
        (caught: unknown) => caught,
      );

      expect(error).toBeInstanceOf(ClientUserProvisionRolledBackError);
      const userId = (error as ClientUserProvisionRolledBackError).userId;
      expect(
        world.calls.filter((call) =>
          ['recordProvisioned', 'recordProvisionReverted', 'deleteUser'].includes(call),
        ),
      ).toEqual(['recordProvisioned', 'recordProvisionReverted', 'deleteUser']);
      expect(world.reversals).toEqual([{ userId, reason: 'record_failed' }]);
      expect(world.trail).toEqual([{ userId, event: 'account.provision_reverted' }]);
      expect(accountOf(world)).toBeUndefined();
    });

    it('E-50: a creation whose answer was lost and is taken back is reverted with the reason answer_lost', async () => {
      const world = worldWithTwoClients();
      world.loseAnswerOf('createClientUser');

      const error: unknown = await provisionClientUser(deps(world), ceoPrincipal, INPUT).catch(
        (caught: unknown) => caught,
      );

      expect(error).toBeInstanceOf(ClientUserProvisionRolledBackError);
      expect(world.reversals).toEqual([
        { userId: (error as ClientUserProvisionRolledBackError).userId, reason: 'answer_lost' },
      ]);
      expect(world.calls.indexOf('recordProvisionReverted')).toBeLessThan(
        world.calls.indexOf('deleteUser'),
      );
    });

    it('E-55: an answer without an id, taken back by the e-mail, is reverted too', async () => {
      const world = worldWithTwoClients();
      world.answerNextCreationWithoutId();

      await expect(provisionClientUser(deps(world), ceoPrincipal, INPUT)).rejects.toBeInstanceOf(
        ClientUserProvisionRolledBackError,
      );

      expect(world.reversals).toHaveLength(1);
      expect(world.reversals[0]?.reason).toBe('answer_lost');
    });

    it('SEC-04: a database that no longer sees a CEO: the reversal is recorded, the account deleted, and the answer is the 403', async () => {
      const world = worldWithTwoClients();
      const users = {
        ...world.users,
        recordProvisioned: () =>
          Promise.resolve({ ok: false as const, error: new ForbiddenError('denied') }),
      };

      const result = await provisionClientUser({ ...deps(world), users }, ceoPrincipal, INPUT);

      expect(!result.ok && result.error).toBeInstanceOf(ForbiddenError);
      expect(world.reversals).toHaveLength(1);
      expect(accountOf(world)).toBeUndefined();
    });

    it('a reversal that fails once is recorded on the second try, and the account is still deleted', async () => {
      const world = worldWithTwoClients();
      world.failNext('recordProvisioned');
      world.failNext('recordProvisionReverted', 1);

      await expect(provisionClientUser(deps(world), ceoPrincipal, INPUT)).rejects.toBeInstanceOf(
        ClientUserProvisionRolledBackError,
      );

      expect(world.calls.filter((call) => call === 'recordProvisionReverted')).toHaveLength(2);
      expect(world.reversals).toHaveLength(1);
      expect(accountOf(world)).toBeUndefined();
    });

    it('fail closed: when the reversal cannot be recorded (an outage on both tries) the account is NOT deleted, and the orphan error says why', async () => {
      const world = worldWithTwoClients();
      world.failNext('recordProvisioned');
      world.failNext('recordProvisionReverted', 2);

      const error: unknown = await provisionClientUser(deps(world), ceoPrincipal, INPUT).catch(
        (caught: unknown) => caught,
      );

      expect(error).toBeInstanceOf(ClientUserProvisionOrphanedError);
      expect(error).toMatchObject({
        reason: 'record_failed',
        deleteFailure: { kind: 'SERVICE_UNAVAILABLE' },
      });
      expect(world.calls).not.toContain('deleteUser');
      expect(world.reversals).toEqual([]);
      const orphan = accountOf(world);
      expect(orphan).toBeDefined();
      expect((error as ClientUserProvisionOrphanedError).userId).toBe(orphan?.id);
    });

    it('fail closed: a refusal of the reversal (a CEO the database no longer sees) is final: no second try, no deletion', async () => {
      const world = worldWithTwoClients();
      world.failNext('recordProvisioned');
      world.refuseNext('recordProvisionReverted', new ForbiddenError('denied'));

      const error: unknown = await provisionClientUser(deps(world), ceoPrincipal, INPUT).catch(
        (caught: unknown) => caught,
      );

      expect(error).toBeInstanceOf(ClientUserProvisionOrphanedError);
      expect(error).toMatchObject({ deleteFailure: { kind: 'FORBIDDEN' } });
      expect(world.calls.filter((call) => call === 'recordProvisionReverted')).toHaveLength(1);
      expect(world.calls).not.toContain('deleteUser');
      expect(accountOf(world)).toBeDefined();
    });

    it('F-114: Forbidden on the record and then Forbidden on the reversal (a CEO the database no longer sees) is DETERMINISTIC: 503 orphaned, the account stays, nothing is deleted without a trace', async () => {
      const world = worldWithTwoClients();
      const users = {
        ...world.users,
        recordProvisioned: () =>
          Promise.resolve({ ok: false as const, error: new ForbiddenError('denied') }),
      };
      world.refuseNext('recordProvisionReverted', new ForbiddenError('denied'));

      const error: unknown = await provisionClientUser(
        { ...deps(world), users },
        ceoPrincipal,
        INPUT,
      ).catch((caught: unknown) => caught);

      // not the 403 the record answered: the account exists and nobody was given its password
      expect(error).toBeInstanceOf(ClientUserProvisionOrphanedError);
      expect(error).toBeInstanceOf(ServiceUnavailableError);
      expect(error).toMatchObject({
        reason: 'record_failed',
        deleteFailure: { kind: 'FORBIDDEN' },
      });
      expect(world.calls.filter((call) => call === 'recordProvisionReverted')).toHaveLength(1);
      expect(world.calls).not.toContain('deleteUser');
      expect(world.reversals).toEqual([]);
      const orphan = accountOf(world);
      expect(orphan).toBeDefined();
      expect((error as ClientUserProvisionOrphanedError).userId).toBe(orphan?.id);
    });

    it('F-117: a login that is in use, or that already has account.provisioned, is refused by the reversal in the fake as the function does', async () => {
      const world = worldWithTwoClients();
      // a seeded login has its definitive password: not an unused login
      const refusedOld = await world.users.recordProvisionReverted(USER_A1, 'record_failed');
      expect(!refusedOld.ok && refusedOld.error).toBeInstanceOf(NotFoundError);
      // a young login that already has its record
      const young = world.seed({
        id: '00000000-0000-4000-8000-0000000000a9',
        clientId: CLIENT_A,
        email: 'young@cliente.test',
        mustChangePassword: true,
        provisioned: true,
        createdAt: new Date(),
      });
      const refusedRecorded = await world.users.recordProvisionReverted(young.id, 'record_failed');
      expect(!refusedRecorded.ok && refusedRecorded.error).toBeInstanceOf(ValidationError);
      expect(world.reversals).toEqual([]);
    });

    it('F-93: a second record of the same login is refused by the fake with a ValidationError, as the function does', async () => {
      const world = worldWithTwoClients();
      const created = await provisionClientUser(deps(world), ceoPrincipal, INPUT);
      expect(created.ok).toBe(true);
      if (!created.ok) return;

      const again = await world.users.recordProvisioned(created.value.user.id);

      expect(!again.ok && again.error).toBeInstanceOf(ValidationError);
      expect(world.trail.filter((entry) => entry.event === 'account.provisioned')).toHaveLength(1);
    });

    it('a deletion that fails after the reversal was recorded: the orphan error carries the deletion failure, and the reversal stays on the trail', async () => {
      const world = worldWithTwoClients();
      world.failNext('recordProvisioned');
      world.failNext('deleteUser', 2);

      const error: unknown = await provisionClientUser(deps(world), ceoPrincipal, INPUT).catch(
        (caught: unknown) => caught,
      );

      expect(error).toBeInstanceOf(ClientUserProvisionOrphanedError);
      expect(world.reversals).toHaveLength(1);
      expect(accountOf(world)).toBeDefined();
    });

    it('a successful provisioning records no reversal at all', async () => {
      const world = worldWithTwoClients();

      await provisionClientUser(deps(world), ceoPrincipal, INPUT);

      expect(world.calls).not.toContain('recordProvisionReverted');
      expect(world.reversals).toEqual([]);
    });
  });

  describe('code review 5: what the compensation reports', () => {
    it('E-23: the rolled-back error carries the id of the account taken back, for the log', async () => {
      const world = worldWithTwoClients();
      world.failNext('recordProvisioned');

      const error: unknown = await provisionClientUser(deps(world), ceoPrincipal, INPUT).catch(
        (caught: unknown) => caught,
      );

      expect(error).toBeInstanceOf(ClientUserProvisionRolledBackError);
      expect(error).toMatchObject({ reason: 'record_failed' });
      expect(typeof (error as ClientUserProvisionRolledBackError).userId).toBe('string');
    });

    it('E-23: the orphan error says why the last deletion failed (a code and a status, no message)', async () => {
      const world = worldWithTwoClients();
      world.failNext('recordProvisioned');
      world.failNext('deleteUser', 2);

      const error: unknown = await provisionClientUser(deps(world), ceoPrincipal, INPUT).catch(
        (caught: unknown) => caught,
      );

      expect(error).toBeInstanceOf(ClientUserProvisionOrphanedError);
      expect(error).toMatchObject({
        reason: 'record_failed',
        deleteFailure: { kind: 'SERVICE_UNAVAILABLE' },
      });
    });
  });
});
