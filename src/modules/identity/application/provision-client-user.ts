import {
  err,
  ForbiddenError,
  NotFoundError,
  ok,
  ServiceUnavailableError,
  systemClock,
  type Clock,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import {
  MAX_CLIENT_USERS,
  type ClientStatus,
  type ClientUser,
  type ProvisionedClientUser,
} from '../domain/client-user';
import {
  ClientArchivedError,
  ClientUserProvisionAnswerLostError,
  ClientUserProvisionOrphanedError,
  ClientUserProvisionRolledBackError,
  EmailAlreadyRegisteredError,
  UserLimitReachedError,
  type ProvisionTakeBackReason,
} from '../domain/client-user-errors';
import type {
  AccountAdminGateway,
  ClientStatusDirectory,
  ClientUserRepository,
} from '../domain/client-user-ports';
import { safeCauseOf, type SafeCause } from '../domain/safe-cause';
import { generateTemporaryPassword } from '../domain/temporary-password';
import { ceoOnly } from './client-user-access';

export type ProvisionClientUserDeps = {
  readonly clients: ClientStatusDirectory;
  readonly users: ClientUserRepository;
  readonly accounts: AccountAdminGateway;
  /** Default: `generateTemporaryPassword` (20 characters from the platform CSPRNG). Tests inject one. */
  readonly generatePassword?: () => string;
  /** Default: the system clock. It stamps the start of the attempt (see `isOwnLogin`). */
  readonly clock?: Clock;
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

/** What the use case read about the client before it created anything. */
type ClientState = { readonly client: ClientStatus; readonly users: readonly ClientUser[] };

/** 404 when the client does not exist; otherwise its status and its logins. */
async function readState(
  deps: ProvisionClientUserDeps,
  clientId: string,
): Promise<Result<ClientState, DomainError>> {
  const client = await deps.clients.status(clientId);
  if (client === null) {
    return err(new NotFoundError('client not found', { detail: 'Client not found.' }));
  }
  const listed = await deps.users.list(clientId);
  if (!listed.ok) return listed;
  return ok({ client, users: listed.value });
}

/** 422 `CLIENT_ARCHIVED` (E-16) and 422 `USER_LIMIT_REACHED` (E-18): the refusals the trigger also makes. */
function roomRefusal(state: ClientState): DomainError | null {
  if (state.client.archived) return new ClientArchivedError();
  if (state.users.length >= MAX_CLIENT_USERS) return new UserLimitReachedError();
  return null;
}

/**
 * The checks the use case makes BEFORE creating anything, so the answer is a clean 404, 409 or 422.
 * They are not the deciding ones: the profile trigger of the database re-checks the client and the
 * limit under a lock on the client (F-58), and Auth's unique index decides the e-mail.
 *
 * A login of THIS client that already has the e-mail is the 409 of E-17 right here. It also keeps a
 * login that existed before the request out of the look behind a failed creation (see `ownLogin`).
 */
async function checkBeforeCreating(
  deps: ProvisionClientUserDeps,
  input: ProvisionClientUserInput,
): Promise<Result<ClientState, DomainError>> {
  const state = await readState(deps, input.clientId);
  if (!state.ok) return state;
  if (state.value.client.archived) return err(new ClientArchivedError());
  if (state.value.users.some((user) => user.email.toLowerCase() === input.email)) {
    return err(new EmailAlreadyRegisteredError());
  }
  const refusal = roomRefusal(state.value);
  return refusal === null ? state : err(refusal);
}

/**
 * The logins that might be the one this very request created, found by their e-mail among the logins of
 * the client now: they were not there before the request (`known`), and they are exactly what a new login
 * is (the temporary password still in use, never signed in). A login that existed before, or one somebody
 * already uses, is never a candidate.
 *
 * A candidate is a CANDIDATE, not proof: another CEO may have provisioned the same address in the same
 * client between the snapshot and the failure, and that login looks just the same. See `isOwnLogin`.
 */
function candidateLogins(
  state: ClientState,
  known: readonly ClientUser[],
  email: string,
): readonly ClientUser[] {
  const knownIds = new Set(known.map((user) => user.id));
  return state.users.filter(
    (user) =>
      user.email.toLowerCase() === email &&
      !knownIds.has(user.id) &&
      user.mustChangePassword &&
      user.lastSignInAt === null,
  );
}

/**
 * The tolerance for the clock of the database (which stamps `createdAt`) running a little behind the
 * clock of this process (which stamps the start of the attempt). Erring this way only ever fails closed:
 * an own login that looks older than the attempt is not deleted.
 */
const CLOCK_SKEW_TOLERANCE_MS = 2_000;

/**
 * Is this candidate the login of THIS attempt, so that deleting it undoes only what the attempt did?
 * Only when it is the ONLY candidate AND it was created at or after the moment the attempt started
 * (less the skew tolerance): a login another CEO provisioned a moment before, with the same e-mail, was
 * created before the attempt and is never ours. With more than one candidate nobody can tell which is
 * ours, and nothing is deleted (M1: fail closed, no destructive action on a guess).
 */
function isOwnLogin(
  candidates: readonly ClientUser[],
  attemptStartedAt: Date,
): ClientUser | undefined {
  const [only] = candidates;
  if (candidates.length !== 1 || only === undefined) return undefined;
  const earliest = attemptStartedAt.getTime() - CLOCK_SKEW_TOLERANCE_MS;
  return only.createdAt.getTime() >= earliest ? only : undefined;
}

type Removal =
  { readonly removed: true } | { readonly removed: false; readonly failure: SafeCause };

/** Deletes the account, trying again once. When it cannot, says why (a code and a status only). */
async function removeAccount(accounts: AccountAdminGateway, userId: string): Promise<Removal> {
  let failure: SafeCause = { kind: 'UNKNOWN' };
  for (let attempt = 1; attempt <= DELETE_ATTEMPTS; attempt += 1) {
    try {
      await accounts.deleteUser(userId);
      return { removed: true };
    } catch (error) {
      failure = safeCauseOf(error);
    }
  }
  return { removed: false, failure };
}

/**
 * Takes an account this request created back, and ends the request with the 503 that says how it went:
 * deleted (`ClientUserProvisionRolledBackError`) or not (`ClientUserProvisionOrphanedError`, with the id
 * and why the deletion failed, for the log). Always throws.
 */
async function takeBack(
  deps: ProvisionClientUserDeps,
  userId: string,
  reason: ProvisionTakeBackReason,
  cause: unknown,
): Promise<never> {
  const removal = await removeAccount(deps.accounts, userId);
  const safe = safeCauseOf(cause);
  if (removal.removed) {
    throw new ClientUserProvisionRolledBackError(userId, reason, { cause: safe });
  }
  throw new ClientUserProvisionOrphanedError(userId, reason, removal.failure, { cause: safe });
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
 * What a creation that failed with a 503-class error (an outage, a refusal of the profile trigger that
 * Auth reports as a 500 it cannot name, or an answer without an id) really was. The Auth server cannot
 * say, so the use case looks at the client again, in this order:
 * 1. is a login with the e-mail there that was not there before? Then the creation WORKED and only its
 *    answer was lost (E-50, E-55), or ANOTHER CEO provisioned the same address a moment ago. If there is
 *    exactly one candidate and it was created at or after the start of this attempt, it is ours: the
 *    account is taken back and the answer stays a 503. Otherwise (more than one, or an older one) nothing
 *    is deleted: `ClientUserProvisionAnswerLostError` (503) carries the ids for the log. Never a 422,
 *    which would say "refused" about a login that exists and that nobody was given the password of (F-90);
 * 2. only when there is none: is the client archived now, or full? Then the trigger refused it (E-52): 422.
 * Anything else, or a look that itself fails, leaves the original failure standing.
 */
async function explainFailedCreation(
  deps: ProvisionClientUserDeps,
  input: ProvisionClientUserInput,
  known: readonly ClientUser[],
  attemptStartedAt: Date,
  cause: unknown,
): Promise<DomainError | null> {
  let state: Result<ClientState, DomainError>;
  try {
    state = await readState(deps, input.clientId);
  } catch {
    return null;
  }
  if (!state.ok) return null;

  const candidates = candidateLogins(state.value, known, input.email);
  if (candidates.length > 0) {
    const own = isOwnLogin(candidates, attemptStartedAt);
    if (own !== undefined) return takeBack(deps, own.id, 'answer_lost', cause);
    // fail closed: never delete on a guess
    throw new ClientUserProvisionAnswerLostError(
      candidates.map((candidate) => candidate.id),
      { cause: safeCauseOf(cause) },
    );
  }
  return roomRefusal(state.value);
}

/**
 * `POST /admin/clients/{clientId}/users` (RF-07, AC-12, E-16 to E-18, E-23, E-50 to E-55). A CEO
 * provisions a login for a client; the server generates the temporary password (20 characters, CSPRNG),
 * creates the account WITH it in one Auth call (the baseline that proves the first password change, ADR
 * 0007) and hands it back once. It is a secret: it is never logged and never stored.
 *
 * 1. The client exists, is not archived, has no login with that e-mail and has room (checks above:
 *    clean 404, 422, 409 and 422).
 * 2. The account is created. `email_exists` is 409 `EMAIL_ALREADY_REGISTERED` (E-17). After a failure that
 *    looks like an outage the use case finds out what happened before it answers (`explainFailedCreation`).
 * 3. `record_account_provisioned` and a read-back. This is the one step that can fail AFTER the account
 *    exists. If it does (E-23), the account is deleted again (the compensation) and the answer is 503:
 *    nothing is left and nobody saw the password. If the deletion fails too, `ClientUserProvisionOrphanedError`
 *    says so and carries the id for the log: the CEO finds the login in the list and resets or disables it.
 */
export async function provisionClientUser(
  deps: ProvisionClientUserDeps,
  principal: Principal,
  input: ProvisionClientUserInput,
): Promise<Result<ProvisionedClientUser, DomainError>> {
  const forbidden = ceoOnly(principal);
  if (forbidden !== null) return err(forbidden);

  const before = await checkBeforeCreating(deps, input);
  if (!before.ok) return before;

  const temporaryPassword = (deps.generatePassword ?? generateTemporaryPassword)();

  // the moment this attempt starts: a login created before it is never the attempt's own
  const attemptStartedAt = (deps.clock ?? systemClock).now();
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
      const explained = await explainFailedCreation(
        deps,
        input,
        before.value.users,
        attemptStartedAt,
        error,
      );
      if (explained !== null) return err(explained);
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
    return takeBack(deps, userId, 'record_failed', cause);
  }

  if (!outcome.ok) {
    // a database that no longer sees a CEO is that answer; anything else here is not the CEO's doing
    if (outcome.error instanceof ForbiddenError) {
      const removal = await removeAccount(deps.accounts, userId);
      if (!removal.removed) {
        throw new ClientUserProvisionOrphanedError(userId, 'record_failed', removal.failure, {
          cause: safeCauseOf(outcome.error),
        });
      }
      return outcome;
    }
    return takeBack(deps, userId, 'record_failed', outcome.error);
  }

  return ok({ user: outcome.value, temporaryPassword });
}
