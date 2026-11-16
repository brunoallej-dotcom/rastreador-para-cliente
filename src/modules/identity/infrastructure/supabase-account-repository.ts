import type { SupabaseClient } from '@supabase/supabase-js';
import { z } from 'zod';
import type { Database } from '@/shared/db/database.types';
import { upstreamFailure } from '@/shared/db/upstream-errors';
import {
  err,
  ForbiddenError,
  NotFoundError,
  ok,
  ServiceUnavailableError,
  ValidationError,
  type DomainError,
  type Result,
} from '@/shared/kernel';
import type { Logger } from '@/shared/observability/logger';
import type { ClientUser } from '../domain/client-user';
import type { ClientUserRepository } from '../domain/client-user-ports';

/** Postgres: `insufficient_privilege`, what the database functions raise for a denied caller. */
const INSUFFICIENT_PRIVILEGE = '42501';
/** Postgres: `raise_exception`, with the application code as the message (spec §3.7). */
const RAISE_EXCEPTION = 'P0001';
const CHECK_VIOLATION = '23514';
const STRING_DATA_RIGHT_TRUNCATION = '22001';
const NOT_FOUND_MESSAGE = 'NOT_FOUND';
const INVALID_INPUT_MESSAGE = 'INVALID_INPUT';
/**
 * Postgres rolled the whole transaction back and nothing of it persisted, so repeating the call is
 * safe: `deadlock_detected` and `serialization_failure`. PostgREST answers both with HTTP 500, which
 * `upstreamFailure` would already turn into a 503; the SQLSTATE is matched on its own, whatever the
 * status, so a PostgREST that changes it does not turn a retry into a 500.
 */
const ROLLED_BACK_TRANSIENTLY: ReadonlySet<string> = new Set(['40P01', '40001']);

/** A `timestamptz` as PostgREST sends it: any sub-second precision, always with an offset. */
const timestampSchema = z.iso.datetime({ offset: true });

/** One row of `list_client_users`, read as untrusted data: what does not match fails closed (500). */
const loginRowSchema = z.object({
  user_id: z.guid(),
  email: z.string().min(1),
  display_name: z.string().min(1),
  // the generated type says `string`, the function returns NULL for an enabled login
  disabled_at: timestampSchema.nullable(),
  must_change_password: z.boolean(),
  last_sign_in_at: timestampSchema.nullable(),
  created_at: timestampSchema,
});

const toClientUser = (row: z.infer<typeof loginRowSchema>): ClientUser => ({
  id: row.user_id,
  email: row.email,
  displayName: row.display_name,
  disabled: row.disabled_at !== null,
  mustChangePassword: row.must_change_password,
  lastSignInAt: row.last_sign_in_at === null ? null : new Date(row.last_sign_in_at),
  createdAt: new Date(row.created_at),
});

/**
 * What may travel as the `cause` of an error: the SQLSTATE and the HTTP status, never the message or
 * the details of the database error. The logger writes the `cause` chain of every 5xx error, and a
 * message can carry a row (an e-mail, a name).
 */
const safeCause = (error: { code?: string }, status: number) => ({
  code: error.code ?? '',
  status,
});

const loginNotFound = (operation: string) =>
  new NotFoundError(`${operation} found no such client login`, {
    detail: 'Client login not found.',
  });

export type AccountRepositoryOptions = {
  readonly logger: Pick<Logger, 'warn'>;
};

/**
 * `ClientUserRepository` over Supabase, AS THE CEO who is calling: the request-scoped client (the
 * session of the request, never the admin client) and the CEO functions of the database, which check
 * the role, the `aal2` attestation and the target by themselves and write the audit event in the same
 * transaction (spec §3.7). Nothing here writes a table.
 *
 * Whatever comes back is validated with Zod. Database errors are mapped by SQLSTATE and message
 * (spec §3.7): a denied caller is `ForbiddenError`, `NOT_FOUND` is `NotFoundError`, `INVALID_INPUT` is a
 * 400, a rolled-back transaction (`40P01`, `40001`) is a 503 that is safe to repeat; an unmapped one is
 * an unexpected error (500) and a slow or dead database is a 503 (E-21).
 */
export function createSupabaseAccountRepository(
  supabase: SupabaseClient<Database>,
  options: AccountRepositoryOptions,
): ClientUserRepository {
  /** Maps what a function raised. Returns the domain error, or throws for the unexpected. */
  function refusalOf(
    operation: string,
    error: { code?: string; message: string },
    status: number,
  ): DomainError {
    if (error.code === INSUFFICIENT_PRIVILEGE) {
      // Layer 1 should have stopped this caller: a denial here means it was bypassed (spec §3.7).
      options.logger.warn({ event: 'authz.database_denied', operation }, 'authz.database_denied');
      return new ForbiddenError(`${operation} denied the caller`, { detail: 'Access denied.' });
    }
    if (error.code === RAISE_EXCEPTION && error.message === NOT_FOUND_MESSAGE) {
      return loginNotFound(operation);
    }
    if (
      (error.code === RAISE_EXCEPTION && error.message === INVALID_INPUT_MESSAGE) ||
      error.code === CHECK_VIOLATION ||
      error.code === STRING_DATA_RIGHT_TRUNCATION
    ) {
      return new ValidationError(
        'the database refused the input',
        [{ path: 'body', message: 'Invalid input' }],
        { cause: { code: error.code } },
      );
    }
    if (error.code !== undefined && ROLLED_BACK_TRANSIENTLY.has(error.code)) {
      // 503 with Retry-After, like any transient failure: nothing persisted, so the CEO repeats it
      throw new ServiceUnavailableError(`${operation}: the transaction was rolled back`, {
        cause: safeCause(error, status),
      });
    }
    throw upstreamFailure(operation, safeCause(error, status), status);
  }

  /** The functions that return nothing: the call, and what it raised. */
  async function write(
    operation: string,
    run: () => PromiseLike<{ error: { code?: string; message: string } | null; status: number }>,
  ): Promise<Result<void, DomainError>> {
    const { error, status } = await run();
    if (error) return err(refusalOf(operation, error, status));
    return ok(undefined);
  }

  return {
    async list(clientId) {
      const { data, error, status } = await supabase.rpc('list_client_users', {
        p_client_id: clientId,
      });
      if (error) {
        const refusal = refusalOf('list_client_users', error, status);
        // an unknown client is a 404 about the CLIENT here, not about a login
        return err(
          refusal instanceof NotFoundError
            ? new NotFoundError('list_client_users found no such client', {
                detail: 'Client not found.',
              })
            : refusal,
        );
      }

      const rows = z.array(loginRowSchema).safeParse(data);
      if (!rows.success) throw new Error('list_client_users returned a row that is not understood');
      return ok(rows.data.map(toClientUser));
    },

    recordProvisioned: (userId) =>
      write('record_account_provisioned', () =>
        supabase.rpc('record_account_provisioned', { p_user_id: userId }),
      ),

    setDisabled: (userId, disabled) =>
      write('set_account_disabled', () =>
        supabase.rpc('set_account_disabled', { p_user_id: userId, p_disabled: disabled }),
      ),

    setDisplayName: (userId, displayName) =>
      write('set_account_display_name', () =>
        supabase.rpc('set_account_display_name', {
          p_user_id: userId,
          p_display_name: displayName,
        }),
      ),

    requirePasswordChange: (userId) =>
      write('require_password_change', () =>
        supabase.rpc('require_password_change', { p_user_id: userId }),
      ),
  };
}
