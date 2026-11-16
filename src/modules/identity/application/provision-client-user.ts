import {
  err,
  ForbiddenError,
  NotFoundError,
  ok,
  ServiceUnavailableError,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import {
  MAX_CLIENT_USERS,
  type ClientUser,
  type ProvisionedClientUser,
} from '../domain/client-user';
import {
  ClientArchivedError,
  ClientUserProvisionOrphanedError,
  ClientUserProvisionRolledBackError,
  UserLimitReachedError,
} from '../domain/client-user-errors';
import type {
  AccountAdminGateway,
  ClientStatusDirectory,
  ClientUserRepository,
} from '../domain/client-user-ports';
import { generateTemporaryPassword } from '../domain/temporary-password';
import { ceoOnly } from './client-user-access';

export type ProvisionClientUserDeps = {
  readonly clients: ClientStatusDirectory;
  readonly users: ClientUserRepository;
  readonly accounts: AccountAdminGateway;
  /** Default: `generateTemporaryPassword` (20 characters from the platform CSPRNG). Tests inject one. */
  readonly generatePassword?: () => string;
};

export type ProvisionClientUserInput = {
  readonly clientId: string;
  /** Already normalized (`normalizeEmail`) and validated by the schema. */
  readonly email: string;
  /** Already normalized (NFC, trimmed) and validated by the schema. */
  readonly displayName: string;
};

/** The compensation tries to delete the account this many times (a blip must not leave an orphan). */
const DELETE_ATTEMPTS = 2;

/**
 * 404 when the client does not exist; 422 `CLIENT_ARCHIVED` (E-16) and 422 `USER_LIMIT_REACHED` (E-18)
 * otherwise. These are the checks the use case makes BEFORE creating anything, so the answer is a clean
 * 422. They are not the deciding ones: the profile trigger of the database re-checks both under a lock
 * on the client (F-58), which is what holds when two requests race.
 */
async function checkRoom(
  deps: ProvisionClientUserDeps,
  clientId: string,
): Promise<Result<void, DomainError>> {
  const client = await deps.clients.status(clientId);
  if (client === null) {
    return err(new NotFoundError('client not found', { detail: 'Client not found.' }));
  }
  if (client.archived) return err(new ClientArchivedError());

  const listed = await deps.users.list(clientId);
  if (!listed.ok) return listed;
  if (listed.value.length >= MAX_CLIENT_USERS) return err(new UserLimitReachedError());
  return ok(undefined);
}

/**
 * The refusal behind a failed creation, if there is one. The Auth server cannot tell a refusal of the
 * profile trigger (archived client, limit reached: both raised at COMMIT) from an outage, so a creation
 * that fails with a 503-class error is explained by asking again. Whatever that second look throws, the
 * original failure stands.
 */
async function refusalBehind(
  deps: ProvisionClientUserDeps,
  clientId: string,
): Promise<DomainError | null> {
  try {
    const room = await checkRoom(deps, clientId);
    return room.ok ? null : room.error;
  } catch {
    return null;
  }
}

/** Deletes the account, trying again once. `true` when it is gone. */
async function removeAccount(accounts: AccountAdminGateway, userId: string): Promise<boolean> {
  for (let attempt = 1; attempt <= DELETE_ATTEMPTS; attempt += 1) {
    try {
      await accounts.deleteUser(userId);
      return true;
    } catch {
      // try again; the failure is told to the operator by the orphan error if the last attempt fails too
    }
  }
  return false;
}

/** The step that must succeed before the password is handed over: the audit record and the read-back. */
async function recordAndRead(
  deps: ProvisionClientUserDeps,
  clientId: string,
  userId: string,
): Promise<Result<ClientUser, DomainError>> {
  const recorded = await deps.users.recordProvisioned(userId);
  if (!recorded.ok) return recorded;

  // The 201 shows the login as the list will show it (the profile's own timestamps).
  const listed = await deps.users.list(clientId);
  if (!listed.ok) return listed;
  const user = listed.value.find((candidate) => candidate.id === userId);
  if (user === undefined) {
    return err(new NotFoundError('the new login is not in the list', { detail: 'Not found.' }));
  }
  return ok(user);
}

/**
 * `POST /admin/clients/{clientId}/users` (RF-07, AC-12, E-16 to E-18, E-23). A CEO provisions a login
 * for a client; the server generates the temporary password (20 characters, CSPRNG), creates the
 * account WITH it in one Auth call (the baseline that proves the first password change, ADR 0007) and
 * hands it back once. It is a secret: it is never logged and never stored.
 *
 * 1. The client exists, is not archived and has room (checks above: clean 404 and 422s).
 * 2. The account is created. `email_exists` is 409 `EMAIL_ALREADY_REGISTERED` (E-17). A failure that
 *    looks like an outage is explained by looking again (the trigger's refusals arrive that way), so a
 *    race that archives the client or fills it is a 422, not a 503.
 * 3. `record_account_provisioned` and a read-back. This is the one step that can fail AFTER the account
 *    exists. If it does (E-23), the account is deleted again (the compensation) and the answer is 503:
 *    nothing is left and nobody saw the password. If the deletion fails too, `ClientUserProvisionOrphanedError`
 *    says so and carries the id for the log: the CEO finds the login in the list and resets or disables
 *    it. A creation whose ANSWER was lost (timeout) is the same kind of leftover, found the same way.
 */
export async function provisionClientUser(
  deps: ProvisionClientUserDeps,
  principal: Principal,
  input: ProvisionClientUserInput,
): Promise<Result<ProvisionedClientUser, DomainError>> {
  const forbidden = ceoOnly(principal);
  if (forbidden !== null) return err(forbidden);

  const room = await checkRoom(deps, input.clientId);
  if (!room.ok) return room;

  const temporaryPassword = (deps.generatePassword ?? generateTemporaryPassword)();

  let created: Awaited<ReturnType<AccountAdminGateway['createClientUser']>>;
  try {
    created = await deps.accounts.createClientUser({
      email: input.email,
      displayName: input.displayName,
      clientId: input.clientId,
      temporaryPassword,
    });
  } catch (error) {
    if (error instanceof ServiceUnavailableError) {
      const refusal = await refusalBehind(deps, input.clientId);
      if (refusal !== null) return err(refusal);
    }
    throw error;
  }
  if (!created.ok) return created;
  const userId = created.value.id;

  let outcome: Result<ClientUser, DomainError>;
  try {
    outcome = await recordAndRead(deps, input.clientId, userId);
  } catch (cause) {
    // E-23: the account exists, the record or the read-back did not work
    const removed = await removeAccount(deps.accounts, userId);
    if (!removed) throw new ClientUserProvisionOrphanedError(userId, { cause });
    throw new ClientUserProvisionRolledBackError({ cause });
  }

  if (!outcome.ok) {
    const removed = await removeAccount(deps.accounts, userId);
    if (!removed) throw new ClientUserProvisionOrphanedError(userId, { cause: outcome.error });
    // a database that no longer sees a CEO is that answer; anything else here is not the CEO's doing
    if (outcome.error instanceof ForbiddenError) return outcome;
    throw new ClientUserProvisionRolledBackError({ cause: outcome.error });
  }

  return ok({ user: outcome.value, temporaryPassword });
}
