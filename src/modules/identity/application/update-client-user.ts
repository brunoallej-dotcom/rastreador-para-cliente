import {
  err,
  ServiceUnavailableError,
  ValidationError,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { ClientUser } from '../domain/client-user';
import type {
  AccountAdminGateway,
  BanFailureReason,
  ClientUserNotice,
  ClientUserRepository,
} from '../domain/client-user-ports';
import { UnexpectedAuthAnswerError } from '../domain/errors';
import { ceoOnly, clientLoginNotFound, findClientLogin } from './client-user-access';

export type UpdateClientUserDeps = {
  readonly users: ClientUserRepository;
  readonly accounts: AccountAdminGateway;
  /** Where the use case puts what must be on record but is neither its result nor its error. */
  readonly report?: (notice: ClientUserNotice) => void;
};

export type UpdateClientUserInput = {
  readonly clientId: string;
  readonly userId: string;
  /** `true` disables the login, `false` re-enables it; missing leaves it alone. */
  readonly disabled?: boolean | undefined;
  /** Already normalized and validated; missing leaves it alone. */
  readonly displayName?: string | undefined;
};

const nothingToChange = () =>
  new ValidationError(
    'the update names no field',
    [{ path: 'body', message: 'Must name at least one field to change' }],
    { detail: 'Name at least one field to change.' },
  );

/**
 * `PATCH /admin/clients/{clientId}/users/{userId}` (RF-07, AC-13, E-19, E-24, E-56): renames a login,
 * and disables or re-enables it. A user that is not a login of THAT client is 404, a CEO included (E-19).
 *
 * The order is what keeps a failure in the middle safe, and every step can be repeated, so a 503 is
 * answered by repeating the same PATCH:
 * 1. the rename, and only when the name changes (the database function audits every call, so a rename
 *    to the same name would write a second `account.updated`). It is not about access: if it fails
 *    nothing else was touched;
 * 2. re-enabling: the Auth server is told first (unban), then the database. If the unban fails the login
 *    is still disabled in the database and still blocked. If the database step fails AFTER the unban,
 *    the ban is put back (best effort, reported), so the login stays blocked in both places instead of
 *    "unbanned here, disabled there". Never the reverse order, where the database would say "enabled"
 *    while the Auth server still refuses the sign-in;
 * 3. disabling: the database first (the block that counts: it deletes every session and `current_principal()`
 *    returns nothing), then the ban in the Auth server as a second lock. A ban that fails does not undo
 *    the disable and is not an error for the CEO (E-24): the notice `ban_failed` carries why, and the
 *    handler logs it at `error`. Repeating the PATCH `{ disabled: true }` tries the ban again, which is
 *    why a disable of a login that is already disabled still calls the Auth server. The database
 *    function audits only a change of state, so repeating a disable or an enable writes no second event.
 *
 * Two CEOs disabling and enabling the same login at the same time can interleave the two systems. The
 * worst outcome is "enabled in the database, banned in Auth": the sign-in is refused (fail closed), and
 * the next PATCH of either kind repairs it (F-92a).
 */
export async function updateClientUser(
  deps: UpdateClientUserDeps,
  principal: Principal,
  input: UpdateClientUserInput,
): Promise<Result<ClientUser, DomainError>> {
  const forbidden = ceoOnly(principal);
  if (forbidden !== null) return err(forbidden);
  if (input.disabled === undefined && input.displayName === undefined) {
    return err(nothingToChange());
  }

  const target = await findClientLogin(deps.users, input.clientId, input.userId);
  if (!target.ok) return target;

  if (input.displayName !== undefined && input.displayName !== target.value.displayName) {
    const renamed = await deps.users.setDisplayName(input.userId, input.displayName);
    if (!renamed.ok) return renamed;
  }

  if (input.disabled === false) {
    const enabled = await enable(deps, input.userId);
    if (!enabled.ok) return enabled;
  } else if (input.disabled === true) {
    const disabled = await deps.users.setDisabled(input.userId, true);
    if (!disabled.ok) return disabled;
    const failure = await tryBan(deps.accounts, input.userId);
    if (failure !== null) deps.report?.({ kind: 'ban_failed', reason: failure });
  }

  // The answer is the login as it is now, read after the writes.
  return findClientLogin(deps.users, input.clientId, input.userId);
}

/** The Auth server first, then the database; a database step that fails puts the ban back. */
async function enable(
  deps: UpdateClientUserDeps,
  userId: string,
): Promise<Result<void, DomainError>> {
  const unbanned = await deps.accounts.setBanned(userId, false);
  if (!unbanned.ok) return err(clientLoginNotFound());

  let enabled: Result<void, DomainError>;
  try {
    enabled = await deps.users.setDisabled(userId, false);
  } catch (error) {
    await rebanAfterFailedEnable(deps, userId);
    throw error;
  }
  if (!enabled.ok) await rebanAfterFailedEnable(deps, userId);
  return enabled;
}

async function rebanAfterFailedEnable(deps: UpdateClientUserDeps, userId: string): Promise<void> {
  let failure: BanFailureReason | null;
  try {
    failure = await tryBan(deps.accounts, userId);
  } catch {
    // never let the second failure hide the first one, which the caller is about to report
    failure = 'unexpected';
  }
  deps.report?.({
    kind: 'reban_after_failed_enable',
    rebanned: failure === null,
    ...(failure === null ? {} : { reason: failure }),
  });
}

/**
 * The second lock of a disable. `null` when it is set; otherwise why not, as data (E-24, F-94):
 * `unavailable` (transient), `not_found` or `unexpected`. Only these three are swallowed: an error nobody
 * classified (a bug) is thrown, because it is not something a CEO can retry into working. The disable
 * itself is already in the database either way.
 */
async function tryBan(
  accounts: AccountAdminGateway,
  userId: string,
): Promise<BanFailureReason | null> {
  try {
    const banned = await accounts.setBanned(userId, true);
    return banned.ok ? null : 'not_found';
  } catch (error) {
    if (error instanceof UnexpectedAuthAnswerError) return 'unexpected';
    if (error instanceof ServiceUnavailableError) return 'unavailable';
    throw error;
  }
}
