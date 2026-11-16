import { z } from 'zod';
import { getAdminFacade, type AdminAuthApi } from '@/shared/db/admin-client';
import { isUpstreamUnavailable, upstreamFailure } from '@/shared/db/upstream-errors';
import { err, NotFoundError, ok } from '@/shared/kernel';
import { EmailAlreadyRegisteredError } from '../domain/client-user-errors';
import type { AccountAdminGateway } from '../domain/client-user-ports';
import { UnexpectedAuthAnswerError } from '../domain/errors';

/** What the gateway uses of the Auth Admin API. Injected by the unit tests. */
export type AccountAdminApi = Pick<AdminAuthApi, 'createUser' | 'deleteUser' | 'updateUserById'>;

/**
 * The codes of the Auth server that say what the gateway acts on. `email_exists` is the answer to a
 * creation with an address that already has an account (any role, any client, compared without regard
 * to case); `user_not_found` is the answer to a delete or an update of an id it does not have. The
 * installed `@supabase/auth-js` lists them in its `ErrorCode` union, but the answers are compared as
 * plain strings, like the other gateways of this module do, and the unit tests pin them by value.
 */
const EMAIL_EXISTS_CODES: ReadonlySet<string> = new Set(['email_exists', 'user_already_exists']);
const USER_NOT_FOUND = 'user_not_found';

/**
 * `ban_duration` of a disabled login: a century (the Auth server takes Go durations, in hours at most).
 * The database already blocks the login (`disabled_at`); the ban is the second lock (E-24).
 */
const BAN_DURATION = '876000h';
const UNBAN = 'none';

/** What a successful creation answers; the rest of the user object is not read. */
const createdAnswerSchema = z.object({ user: z.object({ id: z.guid() }) });

const codeOf = (error: { code?: unknown }): string | undefined =>
  typeof error.code === 'string' ? error.code : undefined;

/** What may be kept of an Auth error: its kind, status and code. Its message can echo the e-mail. */
type AuthFailure = {
  readonly name: string;
  readonly status: number | undefined;
  readonly code: string | undefined;
};

const failureOf = (error: { name?: unknown; status?: unknown; code?: unknown }): AuthFailure => ({
  name: typeof error.name === 'string' ? error.name : 'AuthError',
  status: typeof error.status === 'number' ? error.status : undefined,
  code: codeOf(error),
});

/**
 * The failure to throw for an Auth answer nobody mapped: a 503 when the service is slow or down (E-21),
 * and `UnexpectedAuthAnswerError` (also a 503, with the status and code for the log) for anything else,
 * so a rejected key or a changed server never looks like a bug of the request.
 */
function unexpected(
  operation: string,
  error: { name?: unknown; status?: unknown; code?: unknown },
): Error {
  const failure = failureOf(error);
  if (isUpstreamUnavailable(failure)) return upstreamFailure(operation, failure);
  return new UnexpectedAuthAnswerError(
    `${operation}: the Auth server answered something unexpected`,
    { status: failure.status, code: failure.code },
    { cause: failure },
  );
}

/**
 * `AccountAdminGateway` over the Auth Admin API: the one place the client logins use the secret key
 * (ADR 0006), through the narrow facade and only for what Auth alone can do: create an account with its
 * password, delete it, store a new password, ban and unban. It reads and writes no business table and
 * signs nobody in.
 *
 * Nothing it throws or logs carries the e-mail, the password or what the Auth server said: only the
 * kind, the status and the error code. `admin` is injected by the unit tests; production resolves the
 * shared facade at the first call, so building the gateway reads no key.
 */
export function createSupabaseAccountAdminGateway(admin?: AccountAdminApi): AccountAdminGateway {
  const api = (): AccountAdminApi => admin ?? getAdminFacade().authAdmin;

  return {
    async createClientUser({ email, displayName, clientId, temporaryPassword }) {
      let result: Awaited<ReturnType<AccountAdminApi['createUser']>>;
      try {
        // The password goes in the SAME call (ADR 0007), `email_confirm` because there is no mailbox
        // round trip, and the profile is built from `app_metadata` by the trigger, in the transaction.
        result = await api().createUser({
          email,
          password: temporaryPassword,
          email_confirm: true,
          app_metadata: { role: 'client', client_id: clientId, display_name: displayName },
        });
      } catch (cause) {
        throw upstreamFailure('create the login', cause);
      }

      if (result.error) {
        const code = codeOf(result.error);
        if (code !== undefined && EMAIL_EXISTS_CODES.has(code)) {
          return err(new EmailAlreadyRegisteredError());
        }
        // Includes the refusals of the profile trigger (archived client, limit), which the Auth server
        // reports as a 500 it cannot name: the use case looks behind them.
        throw unexpected('create the login', result.error);
      }

      const answer = createdAnswerSchema.safeParse(result.data);
      if (!answer.success) throw new Error('create the login: an answer that is not understood');
      return ok({ id: answer.data.user.id });
    },

    async deleteUser(userId) {
      let result: Awaited<ReturnType<AccountAdminApi['deleteUser']>>;
      try {
        result = await api().deleteUser(userId);
      } catch (cause) {
        throw upstreamFailure('delete the login', cause);
      }
      if (!result.error) return;
      // already gone is what was asked for
      if (codeOf(result.error) === USER_NOT_FOUND) return;
      throw unexpected('delete the login', result.error);
    },

    async setPassword(userId, password) {
      let result: Awaited<ReturnType<AccountAdminApi['updateUserById']>>;
      try {
        result = await api().updateUserById(userId, { password });
      } catch (cause) {
        throw upstreamFailure('store the password', cause);
      }
      if (!result.error) return ok(undefined);
      if (codeOf(result.error) === USER_NOT_FOUND) return err(notFound('store the password'));
      throw unexpected('store the password', result.error);
    },

    async setBanned(userId, banned) {
      let result: Awaited<ReturnType<AccountAdminApi['updateUserById']>>;
      try {
        result = await api().updateUserById(userId, {
          ban_duration: banned ? BAN_DURATION : UNBAN,
        });
      } catch (cause) {
        throw upstreamFailure('ban the login', cause);
      }
      if (!result.error) return ok(undefined);
      if (codeOf(result.error) === USER_NOT_FOUND) return err(notFound('ban the login'));
      throw unexpected('ban the login', result.error);
    },
  };
}

const notFound = (operation: string) =>
  new NotFoundError(`${operation}: the Auth server has no such user`, {
    detail: 'Client login not found.',
  });
