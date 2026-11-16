import {
  getAdminFacade,
  type AdminAuthFailure,
  type AdminAuthResult,
  type AdminFacade,
} from '@/shared/db/admin-client';
import { isUpstreamUnavailable, upstreamFailure } from '@/shared/db/upstream-errors';
import { err, NotFoundError, ok } from '@/shared/kernel';
import {
  ClientUserProvisionUnconfirmedError,
  EmailAlreadyRegisteredError,
} from '../domain/client-user-errors';
import type { AccountAdminGateway } from '../domain/client-user-ports';
import { UnexpectedAuthAnswerError } from '../domain/errors';

/** What the gateway uses of the admin facade: four typed operations on client logins. */
export type AccountAdminApi = Pick<
  AdminFacade,
  'createClientUser' | 'deleteUser' | 'setPassword' | 'setBan'
>;

/**
 * The answer of the Auth server to a creation with an address that already has an account (any role,
 * any client, compared without regard to case), and to a delete or an update of an id it does not have.
 * Compared as plain strings, like the other gateways of this module do, and pinned by value in the unit
 * tests: a type check cannot notice a rename. `user_already_exists` is not mapped on purpose: GoTrue
 * answers `email_exists` to an admin creation (observed on the local stack, GoTrue 2.197), and the other
 * code belongs to the public sign-up.
 */
const EMAIL_EXISTS = 'email_exists';
const USER_NOT_FOUND = 'user_not_found';

/**
 * The failure to throw for an Auth answer nobody mapped: a 503 when the service is slow or down (E-21),
 * and `UnexpectedAuthAnswerError` (also a 503, with the status and code for the log) for anything else,
 * so a rejected key or a changed server never looks like a bug of the request. The failure is already
 * reduced to its kind, status and code by the facade: its message, which can echo the e-mail, is gone.
 */
function unexpected(operation: string, failure: AdminAuthFailure): Error {
  if (isUpstreamUnavailable(failure)) return upstreamFailure(operation, failure);
  return new UnexpectedAuthAnswerError(
    `${operation}: the Auth server answered something unexpected`,
    { status: failure.status, code: failure.code },
    { cause: failure },
  );
}

/**
 * `AccountAdminGateway` over the typed operations of the admin facade: the one place the client logins
 * use the secret key (ADR 0006, F-91), and only for what Auth alone can do: create an account with its
 * password, delete it, store a new password, ban and unban. The facade fixes the role of a new account
 * to `client`, so nothing here can create a CEO. It reads and writes no business table and signs nobody in.
 *
 * Nothing it throws or logs carries the e-mail, the password or what the Auth server said: only the
 * kind, the status and the error code. `admin` is injected by the unit tests; production resolves the
 * shared facade at the first call, so building the gateway reads no key.
 */
export function createSupabaseAccountAdminGateway(admin?: AccountAdminApi): AccountAdminGateway {
  const api = (): AccountAdminApi => admin ?? getAdminFacade();

  /** Runs a call; a throw (instead of an `{ error }`) is a transport failure or a bug. */
  async function call<T>(
    operation: string,
    run: () => Promise<AdminAuthResult<T>>,
  ): Promise<AdminAuthResult<T>> {
    try {
      return await run();
    } catch (cause) {
      throw upstreamFailure(operation, cause);
    }
  }

  return {
    async createClientUser({ email, displayName, clientId, temporaryPassword }) {
      const result = await call('create the login', () =>
        api().createClientUser({ email, password: temporaryPassword, displayName, clientId }),
      );

      if (result.error !== null) {
        if (result.error.code === EMAIL_EXISTS) return err(new EmailAlreadyRegisteredError());
        // Includes the refusals of the profile trigger (archived client, limit), which the Auth server
        // reports as a 500 it cannot name: the use case looks behind them.
        throw unexpected('create the login', result.error);
      }

      // The creation worked. If its answer has no id the account exists and cannot be named: that is
      // not "nothing was created", and not a 500 either (E-55).
      const id = result.data?.id ?? null;
      if (id === null) throw new ClientUserProvisionUnconfirmedError();
      return ok({ id });
    },

    async deleteUser(userId) {
      const result = await call('delete the login', () => api().deleteUser(userId));
      if (result.error === null) return;
      // already gone is what was asked for
      if (result.error.code === USER_NOT_FOUND) return;
      throw unexpected('delete the login', result.error);
    },

    async setPassword(userId, password) {
      const result = await call('store the password', () => api().setPassword(userId, password));
      if (result.error === null) return ok(undefined);
      if (result.error.code === USER_NOT_FOUND) return err(notFound('store the password'));
      throw unexpected('store the password', result.error);
    },

    async setBanned(userId, banned) {
      const result = await call('ban the login', () => api().setBan(userId, banned));
      if (result.error === null) return ok(undefined);
      if (result.error.code === USER_NOT_FOUND) return err(notFound('ban the login'));
      throw unexpected('ban the login', result.error);
    },
  };
}

const notFound = (operation: string) =>
  new NotFoundError(`${operation}: the Auth server has no such user`, {
    detail: 'Client login not found.',
  });
