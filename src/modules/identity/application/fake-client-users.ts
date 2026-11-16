// In-memory world behind the three ports of the client logins (the database as a CEO sees it, the Auth
// Admin API, the client directory), for the unit tests of the use cases. Imported by tests only.
//
// It behaves like the real thing where the use cases depend on it: the profile trigger refuses an
// archived client and a client at the limit, but the Auth server cannot tell that from an outage (it
// throws `ServiceUnavailableError`); the database functions act only on client logins; disabling and
// requiring a password change delete the sessions. A test can make any call fail (`failNext`) or lose
// its answer after it worked (`loseAnswerOf`).
import {
  err,
  NotFoundError,
  ok,
  ServiceUnavailableError,
  type DomainError,
  type Result,
} from '@/shared/kernel';
import { MAX_CLIENT_USERS, type ClientStatus, type ClientUser } from '../domain/client-user';
import {
  ClientUserProvisionUnconfirmedError,
  EmailAlreadyRegisteredError,
} from '../domain/client-user-errors';
import type {
  AccountAdminGateway,
  ClientStatusDirectory,
  ClientUserRepository,
} from '../domain/client-user-ports';

export type FakeAccountRecord = {
  readonly id: string;
  readonly role: 'client' | 'ceo';
  readonly clientId: string | null;
  email: string;
  displayName: string;
  disabled: boolean;
  mustChangePassword: boolean;
  password: string;
  banned: boolean;
  sessions: number;
  /** `account.provisioned` was recorded for it. */
  provisioned: boolean;
  /** How many times `require_password_change` ran for it (each one renews the 72 h). */
  passwordBaselines: number;
  lastSignInAt: Date | null;
  /**
   * The audit events the database functions would have written, in order: `account.provisioned`,
   * `account.disabled` / `account.enabled` (only on a change of state, like the function),
   * `account.updated` (on EVERY rename, like the function) and `account.password_reset` (every call).
   */
  readonly audit: string[];
  readonly createdAt: Date;
};

export type FakeMethod =
  | 'status'
  | 'list'
  | 'recordProvisioned'
  | 'setDisabled'
  | 'setDisplayName'
  | 'requirePasswordChange'
  | 'createClientUser'
  | 'deleteUser'
  | 'setPassword'
  | 'setBanned';

export type FakeClientUsers = {
  readonly clients: ClientStatusDirectory;
  readonly users: ClientUserRepository;
  readonly accounts: AccountAdminGateway;
  /** Every call, in order, as `method`. */
  readonly calls: string[];
  readonly records: Map<string, FakeAccountRecord>;
  /** Adds an account directly (a fixture), without going through the ports. */
  seed(account: Partial<FakeAccountRecord> & Pick<FakeAccountRecord, 'id'>): FakeAccountRecord;
  /** The client row, to archive it or rename it between two calls. */
  readonly clientRows: Map<string, { name: string; archived: boolean }>;
  /**
   * The next `times` calls of `method` throw before doing anything: `ServiceUnavailableError`, or the
   * `error` given (an unexpected answer, a bug).
   */
  failNext(method: FakeMethod, times?: number, error?: Error): void;
  /**
   * The next call of a database method returns `err(error)` before doing anything (a refusal of the
   * caller, a login that is gone): the database answered, and said no.
   */
  refuseNext(
    method: 'recordProvisioned' | 'setDisabled' | 'setDisplayName' | 'requirePasswordChange',
    error: DomainError,
  ): void;
  /**
   * The next creation WORKS and then answers without a user id (the account exists and cannot be named):
   * the gateway throws `ClientUserProvisionUnconfirmedError`.
   */
  answerNextCreationWithoutId(): void;
  /** The next call of `method` does its work and THEN throws `ServiceUnavailableError` (answer lost). */
  loseAnswerOf(method: FakeMethod): void;
  /** Runs right before the Auth server creates an account (to race an archive, or a full client). */
  beforeCreate: (() => void) | undefined;
  /** The accounts of a client, in creation order. */
  accountsOf(clientId: string): FakeAccountRecord[];
};

const unavailable = (method: string) => new ServiceUnavailableError(`${method} unavailable`);

export function createFakeClientUsers(
  clients: readonly (ClientStatus & { readonly name: string })[],
): FakeClientUsers {
  const calls: string[] = [];
  const records = new Map<string, FakeAccountRecord>();
  const clientRows = new Map(
    clients.map((client) => [client.id, { name: client.name, archived: client.archived }]),
  );
  const failures = new Map<FakeMethod, { times: number; error: Error | undefined }>();
  const refusals = new Map<FakeMethod, DomainError>();
  const lost = new Set<FakeMethod>();
  let withoutId = false;
  let sequence = 0;

  /** Registers the call; throws when the test made it fail. Returns whether the answer must be lost. */
  const enter = (method: FakeMethod): boolean => {
    calls.push(method);
    const failure = failures.get(method);
    if (failure !== undefined && failure.times > 0) {
      failure.times -= 1;
      throw failure.error ?? unavailable(method);
    }
    return lost.delete(method);
  };
  /** The refusal the test queued for this database method, if any (consumed). */
  const refusalOf = (method: FakeMethod): Result<never, DomainError> | undefined => {
    const refusal = refusals.get(method);
    if (refusal === undefined) return undefined;
    refusals.delete(method);
    return err(refusal);
  };
  const leave = (loseAnswer: boolean, method: FakeMethod) => {
    if (loseAnswer) throw unavailable(method);
  };

  const toUser = (record: FakeAccountRecord): ClientUser => ({
    id: record.id,
    email: record.email,
    displayName: record.displayName,
    disabled: record.disabled,
    mustChangePassword: record.mustChangePassword,
    lastSignInAt: record.lastSignInAt,
    createdAt: record.createdAt,
  });

  const seed: FakeClientUsers['seed'] = (account) => {
    sequence += 1;
    const record: FakeAccountRecord = {
      role: 'client',
      clientId: null,
      email: `login${sequence}@cliente.test`,
      displayName: `Login ${sequence}`,
      disabled: false,
      mustChangePassword: false,
      password: 'seeded-password',
      banned: false,
      sessions: 1,
      provisioned: true,
      passwordBaselines: 0,
      lastSignInAt: null,
      audit: [],
      createdAt: new Date(Date.UTC(2026, 10, 16, 12, 0, sequence)),
      ...account,
    };
    records.set(record.id, record);
    return record;
  };

  const accountsOf = (clientId: string) =>
    [...records.values()].filter(
      (record) => record.role === 'client' && record.clientId === clientId,
    );

  const clientLogin = (userId: string): FakeAccountRecord | undefined => {
    const record = records.get(userId);
    return record?.role === 'client' ? record : undefined;
  };
  const notFound = (): Result<never, NotFoundError> =>
    err(new NotFoundError('no such client login', { detail: 'Client login not found.' }));

  const directory: ClientStatusDirectory = {
    status(clientId) {
      const lose = enter('status');
      const row = clientRows.get(clientId);
      leave(lose, 'status');
      return Promise.resolve(
        row === undefined ? null : { id: clientId, name: row.name, archived: row.archived },
      );
    },
  };

  const repository: ClientUserRepository = {
    list(clientId) {
      const lose = enter('list');
      leave(lose, 'list');
      if (!clientRows.has(clientId)) {
        return Promise.resolve(
          err(new NotFoundError('no such client', { detail: 'Client not found.' })),
        );
      }
      return Promise.resolve(ok(accountsOf(clientId).map(toUser)));
    },
    recordProvisioned(userId) {
      const lose = enter('recordProvisioned');
      const refusal = refusalOf('recordProvisioned');
      if (refusal !== undefined) return Promise.resolve(refusal);
      const record = clientLogin(userId);
      if (record === undefined) return Promise.resolve(notFound());
      record.provisioned = true;
      record.audit.push('account.provisioned');
      leave(lose, 'recordProvisioned');
      return Promise.resolve(ok(undefined));
    },
    setDisabled(userId, disabled) {
      const lose = enter('setDisabled');
      const refusal = refusalOf('setDisabled');
      if (refusal !== undefined) return Promise.resolve(refusal);
      const record = clientLogin(userId);
      if (record === undefined) return Promise.resolve(notFound());
      // like the function: an event only when the state changes
      if (record.disabled !== disabled)
        record.audit.push(disabled ? 'account.disabled' : 'account.enabled');
      record.disabled = disabled;
      if (disabled) record.sessions = 0;
      leave(lose, 'setDisabled');
      return Promise.resolve(ok(undefined));
    },
    setDisplayName(userId, displayName) {
      const lose = enter('setDisplayName');
      const refusal = refusalOf('setDisplayName');
      if (refusal !== undefined) return Promise.resolve(refusal);
      const record = clientLogin(userId);
      if (record === undefined) return Promise.resolve(notFound());
      record.displayName = displayName;
      // like the function: an event on EVERY call, the same name included
      record.audit.push('account.updated');
      leave(lose, 'setDisplayName');
      return Promise.resolve(ok(undefined));
    },
    requirePasswordChange(userId) {
      const lose = enter('requirePasswordChange');
      const refusal = refusalOf('requirePasswordChange');
      if (refusal !== undefined) return Promise.resolve(refusal);
      const record = clientLogin(userId);
      if (record === undefined) return Promise.resolve(notFound());
      record.mustChangePassword = true;
      record.passwordBaselines += 1;
      record.sessions = 0;
      record.audit.push('account.password_reset');
      leave(lose, 'requirePasswordChange');
      return Promise.resolve(ok(undefined));
    },
  };

  const gateway: AccountAdminGateway = {
    createClientUser(account) {
      const lose = enter('createClientUser');
      fake.beforeCreate?.();
      const taken = [...records.values()].some((record) => record.email === account.email);
      if (taken) return Promise.resolve(err(new EmailAlreadyRegisteredError()));

      // the trigger of the profile, which the Auth server reports as a failure it cannot name
      const row = clientRows.get(account.clientId);
      if (
        row === undefined ||
        row.archived ||
        accountsOf(account.clientId).length >= MAX_CLIENT_USERS
      ) {
        return Promise.reject(unavailable('createClientUser'));
      }
      sequence += 1;
      const id = `00000000-0000-4000-8000-${String(sequence).padStart(12, '0')}`;
      seed({
        id,
        clientId: account.clientId,
        email: account.email,
        displayName: account.displayName,
        password: account.temporaryPassword,
        mustChangePassword: true,
        sessions: 0,
        provisioned: false,
        passwordBaselines: 1,
      });
      leave(lose, 'createClientUser');
      if (withoutId) {
        withoutId = false;
        return Promise.reject(new ClientUserProvisionUnconfirmedError());
      }
      return Promise.resolve(ok({ id }));
    },
    deleteUser(userId) {
      const lose = enter('deleteUser');
      records.delete(userId);
      leave(lose, 'deleteUser');
      return Promise.resolve();
    },
    setPassword(userId, password) {
      const lose = enter('setPassword');
      const record = records.get(userId);
      if (record === undefined) return Promise.resolve(notFound());
      record.password = password;
      // like the real Auth server: replacing a password drops the sessions of the user
      record.sessions = 0;
      leave(lose, 'setPassword');
      return Promise.resolve(ok(undefined));
    },
    setBanned(userId, banned) {
      const lose = enter('setBanned');
      const record = records.get(userId);
      if (record === undefined) return Promise.resolve(notFound());
      record.banned = banned;
      leave(lose, 'setBanned');
      return Promise.resolve(ok(undefined));
    },
  };

  const fake: FakeClientUsers = {
    clients: directory,
    users: repository,
    accounts: gateway,
    calls,
    records,
    seed,
    clientRows,
    failNext: (method, times = 1, error) => void failures.set(method, { times, error }),
    refuseNext: (method, error) => void refusals.set(method, error),
    answerNextCreationWithoutId: () => void (withoutId = true),
    loseAnswerOf: (method) => void lost.add(method),
    beforeCreate: undefined,
    accountsOf,
  };
  return fake;
}
