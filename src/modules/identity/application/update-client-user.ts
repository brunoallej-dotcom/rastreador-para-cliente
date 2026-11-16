import {
  err,
  ok,
  ValidationError,
  type DomainError,
  type Principal,
  type Result,
} from '@/shared/kernel';
import type { ClientUser } from '../domain/client-user';
import type { AccountAdminGateway, ClientUserRepository } from '../domain/client-user-ports';
import { ceoOnly, clientLoginNotFound, findClientLogin } from './client-user-access';

export type UpdateClientUserDeps = {
  readonly users: ClientUserRepository;
  readonly accounts: AccountAdminGateway;
};

export type UpdateClientUserInput = {
  readonly clientId: string;
  readonly userId: string;
  /** `true` disables the login, `false` re-enables it; missing leaves it alone. */
  readonly disabled?: boolean | undefined;
  /** Already normalized and validated; missing leaves it alone. */
  readonly displayName?: string | undefined;
};

export type UpdatedClientUser = {
  readonly user: ClientUser;
  /**
   * `false` only when the login was disabled in the database (so it is blocked) and the Auth server
   * could not be told to ban it (E-24). The handler logs it at `error`; the answer is still 200.
   */
  readonly banSynced: boolean;
};

const nothingToChange = () =>
  new ValidationError(
    'the update names no field',
    [{ path: 'body', message: 'Must name at least one field to change' }],
    { detail: 'Name at least one field to change.' },
  );

/**
 * `PATCH /admin/clients/{clientId}/users/{userId}` (RF-07, AC-13, E-19, E-24): renames a login, and
 * disables or re-enables it. A user that is not a login of THAT client is 404, a CEO included (E-19).
 *
 * The order is what keeps a failure in the middle safe, and every step is idempotent, so a 503 is
 * answered by repeating the same PATCH:
 * 1. the rename (not about access: if it fails nothing else was touched);
 * 2. re-enabling: the Auth server is told first (unban), then the database. If the unban fails the login
 *    is still disabled in the database and still blocked; if the database step fails the login is
 *    unbanned but the database still blocks it. Never the reverse, where the database would say
 *    "enabled" while the Auth server still refuses the sign-in;
 * 3. disabling: the database first (the block that counts: it deletes every session and `current_principal()`
 *    returns nothing), then the ban in the Auth server as a second lock. A failed ban does not undo
 *    the disable and is not an error for the CEO (E-24): `banSynced: false`, which the handler logs. Repeating
 *    the PATCH `{ disabled: true }` tries the ban again.
 */
export async function updateClientUser(
  deps: UpdateClientUserDeps,
  principal: Principal,
  input: UpdateClientUserInput,
): Promise<Result<UpdatedClientUser, DomainError>> {
  const forbidden = ceoOnly(principal);
  if (forbidden !== null) return err(forbidden);
  if (input.disabled === undefined && input.displayName === undefined) {
    return err(nothingToChange());
  }

  const target = await findClientLogin(deps.users, input.clientId, input.userId);
  if (!target.ok) return target;

  if (input.displayName !== undefined) {
    const renamed = await deps.users.setDisplayName(input.userId, input.displayName);
    if (!renamed.ok) return renamed;
  }

  let banSynced = true;
  if (input.disabled === false) {
    const unbanned = await deps.accounts.setBanned(input.userId, false);
    if (!unbanned.ok) return err(clientLoginNotFound());
    const enabled = await deps.users.setDisabled(input.userId, false);
    if (!enabled.ok) return enabled;
  } else if (input.disabled === true) {
    const disabled = await deps.users.setDisabled(input.userId, true);
    if (!disabled.ok) return disabled;
    banSynced = await tryBan(deps.accounts, input.userId);
  }

  // The answer is the login as it is now, read after the writes.
  const current = await findClientLogin(deps.users, input.clientId, input.userId);
  if (!current.ok) return current;
  return ok({ user: current.value, banSynced });
}

/** The second lock of a disable. Whatever goes wrong is reported as `false`, never thrown (E-24). */
async function tryBan(accounts: AccountAdminGateway, userId: string): Promise<boolean> {
  try {
    const banned = await accounts.setBanned(userId, true);
    return banned.ok;
  } catch {
    return false;
  }
}
