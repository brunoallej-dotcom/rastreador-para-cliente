import type { DomainError, NotFoundError, Result } from '@/shared/kernel';
import type { ClientStatus, ClientUser } from './client-user';
import type { EmailAlreadyRegisteredError, ProvisionTakeBackReason } from './client-user-errors';

/**
 * What the application writes to the Auth server in the name of an existing client login, as a closed
 * list (F-92 b): the audit of the intent (`begin_client_login_admin`) is written before each of them.
 * `ban` is the second lock of a disable and the ban put back after a re-enable that failed, `unban` is
 * the first step of a re-enable and `set_password` is the temporary password of a reset. Creating and
 * deleting an account are not on it: the creation has no id to audit yet, and the deletion is the
 * compensation of a provisioning, which has its own event (`recordProvisionReverted`).
 */
export type AuthWriteAction = 'ban' | 'unban' | 'set_password';

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
   * `account.provisioned` for a login just created in the Auth server, and the login as the list shows it
   * (one call, no read-back that could fail after the record, F-93). `err(NotFoundError)` when the account
   * is not a client login, `err(ForbiddenError)` when the database no longer sees a CEO.
   */
  recordProvisioned(userId: string): Promise<Result<ClientUser, DomainError>>;

  /**
   * `account.provision_reverted`, written BEFORE the account that this request created is deleted from the
   * Auth server (F-93): without it a deleted account left an `account.provisioned` with no end. Only for a
   * login nobody has used; a second call for the same login records nothing more.
   */
  recordProvisionReverted(
    userId: string,
    reason: ProvisionTakeBackReason,
  ): Promise<Result<void, DomainError>>;

  /**
   * The audit of the INTENT to write to the Auth server (`begin_client_login_admin`, F-92 b): it checks
   * that the caller is a CEO and that `userId` is a client login of `clientId`, and records the intent in
   * its own transaction. Every Auth write of an existing login comes after it, and a failure here means
   * the Auth server is not touched. `err(NotFoundError)` when the login is not one of that client.
   */
  beginAuthWrite(
    clientId: string,
    userId: string,
    action: AuthWriteAction,
  ): Promise<Result<void, DomainError>>;

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
   * from an outage by the Auth server, so it arrives as a thrown `ServiceUnavailableError`. A success
   * whose answer carries no user id is a thrown `ClientUserProvisionUnconfirmedError` (also a
   * `ServiceUnavailableError`): the account may exist, so nobody may say it was not created.
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
 * Why the second lock of a disable (the ban in the Auth server) could not be set (E-24, F-94):
 * `unavailable` (the Auth server is slow or down: transient, repeating the disable retries it),
 * `not_found` (the Auth server has no such user: the profile and the account disagree),
 * `unexpected` (an answer nobody planned for: a rejected key, a changed server) or `not_audited` (the
 * audit of the intent could not be written, so the Auth server was not called at all, F-92 b).
 */
export type BanFailureReason = 'unavailable' | 'not_found' | 'unexpected' | 'not_audited';

/**
 * Something a use case wants on record that is neither its result nor its error: the handler turns it
 * into an error-level log line (the application layer has no logger). Carries no e-mail, no name, no
 * password.
 */
export type ClientUserNotice =
  /** A disable that the database applied and Auth could not ban (E-24). The answer is still 200. */
  | { readonly kind: 'ban_failed'; readonly reason: BanFailureReason }
  /**
   * A re-enable whose database step failed after the Auth server had lifted the ban (F-92a): the ban
   * was put back (`rebanned`) so the login stays blocked in both places, or could not be (`reason`).
   */
  | {
      readonly kind: 'reban_after_failed_enable';
      readonly rebanned: boolean;
      readonly reason?: BanFailureReason;
    };

/**
 * Reads the client a login belongs to, through the `tracking` module's public index (identity knows a
 * client id as an opaque value). `null` when the client does not exist or the session cannot see it.
 */
export interface ClientStatusDirectory {
  status(clientId: string): Promise<ClientStatus | null>;
}
