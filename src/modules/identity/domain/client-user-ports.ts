import type { DomainError, NotFoundError, Result } from '@/shared/kernel';
import type { ClientStatus, ClientUser } from './client-user';
import type { EmailAlreadyRegisteredError } from './client-user-errors';

/**
 * The logins of clients as the database knows them, read and written AS THE CEO who is calling (the
 * request-scoped client: RLS and the CEO functions of the database decide, the secret key is not
 * involved). Every write is a database function that checks the CEO role, the `aal2` attestation and
 * the target, and writes the audit event in the same transaction.
 *
 * Every method throws `ServiceUnavailableError` when the database is slow or down (E-21).
 */
export interface ClientUserRepository {
  /**
   * The logins of the client (CEO accounts are never among them), oldest first, at most 10.
   * `err(NotFoundError)` when the client does not exist.
   */
  list(clientId: string): Promise<Result<readonly ClientUser[], DomainError>>;

  /**
   * `account.provisioned` for a login just created in the Auth server. `err(NotFoundError)` when the
   * account is not a client login, `err(ForbiddenError)` when the database no longer sees a CEO.
   */
  recordProvisioned(userId: string): Promise<Result<void, DomainError>>;

  /** Disables (and revokes every session of) or re-enables a login. Audits only a change of state. */
  setDisabled(userId: string, disabled: boolean): Promise<Result<void, DomainError>>;

  /** Renames a login. `displayName` is already normalized and validated. */
  setDisplayName(userId: string, displayName: string): Promise<Result<void, DomainError>>;

  /**
   * After the new password is stored in the Auth server: the login must change it at the next sign-in,
   * its 72 h of validity restart, and every session of the user is deleted.
   */
  requirePasswordChange(userId: string): Promise<Result<void, DomainError>>;
}

/** What the Auth server answered to the creation of a login. */
export type CreatedAuthUser = { readonly id: string };

/** Everything a new client login is created from. The password is the temporary one. */
export type NewClientUserAccount = {
  /** Already normalized (`normalizeEmail`) and validated. */
  readonly email: string;
  readonly displayName: string;
  readonly clientId: string;
  readonly temporaryPassword: string;
};

/**
 * The Auth Admin API (the secret key), narrowed to what the client logins need and nothing more
 * (ADR 0006): create a login with its password in the same call, delete one, replace a password, and
 * ban or unban. It never reads or writes business data and never signs anybody in.
 *
 * Every method throws `ServiceUnavailableError` when the Auth server is slow or down (E-21), and a
 * plain error for an answer nobody planned for.
 */
export interface AccountAdminGateway {
  /**
   * Creates the login WITH the password (so the baseline of `mark_password_changed()` is that
   * password, ADR 0007). The database trigger builds the profile from `app_metadata` in the same
   * transaction and refuses an archived client or one at the limit: that refusal is not told apart
   * from an outage by the Auth server, so it arrives as a thrown `ServiceUnavailableError`.
   */
  createClientUser(
    account: NewClientUserAccount,
  ): Promise<Result<CreatedAuthUser, EmailAlreadyRegisteredError>>;

  /** Deletes the account (and with it the profile). An account that is already gone is a success. */
  deleteUser(userId: string): Promise<void>;

  /** Stores a new password. `err(NotFoundError)` when the Auth server has no such user. */
  setPassword(userId: string, password: string): Promise<Result<void, NotFoundError>>;

  /** Bans (a century) or unbans the account in the Auth server. `err(NotFoundError)` when there is no such user. */
  setBanned(userId: string, banned: boolean): Promise<Result<void, NotFoundError>>;
}

/**
 * Reads the client a login belongs to, through the `tracking` module's public index (identity knows a
 * client id as an opaque value). `null` when the client does not exist or the session cannot see it.
 */
export interface ClientStatusDirectory {
  status(clientId: string): Promise<ClientStatus | null>;
}
