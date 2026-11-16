import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { updateClientUser } from '../application/update-client-user';
import { createSupabaseAccountAdminGateway } from '../infrastructure/supabase-account-admin-gateway';
import { createSupabaseAccountRepository } from '../infrastructure/supabase-account-repository';
import { toClientUserDto } from './client-user.dto';
import { CLIENT_USER_WRITE_RULE } from './client-user-rate-limits';
import { clientUserParamsSchema, updateClientUserBodySchema } from './client-user.schema';

/**
 * `PATCH /admin/clients/{clientId}/users/{userId}` (operationId `updateClientUser`). Policy equal to
 * the contract: role ceo only, `allowPending: []`, user 60 / min in the shared `writes` counter.
 * Renames, disables or re-enables a login; the body must name at least one of `disabled` and
 * `displayName`. A user that is not a login of the client in the path is a 404 (E-19).
 *
 * A disable that the database applied but the Auth server could not ban is still a 200 (E-24): the
 * login is blocked by the database, and the log carries an error-level event for it.
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createUpdateClientUserHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [CLIENT_USER_WRITE_RULE],
      params: clientUserParamsSchema,
      body: updateClientUserBodySchema,
    },
    async ({ request, requestId, cookies, logger, principal, params, body }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });

      const result = await updateClientUser(
        {
          users: createSupabaseAccountRepository(supabase, { logger }),
          accounts: createSupabaseAccountAdminGateway(),
        },
        principal,
        {
          clientId: params.clientId,
          userId: params.userId,
          disabled: body.disabled,
          displayName: body.displayName,
        },
      );
      if (!result.ok) return result.error;

      if (!result.value.banSynced) {
        // The database blocks the login already; the second lock is missing until the next
        // `{ disabled: true }` (idempotent) or a sign-in attempt that Auth refuses by itself.
        logger.error(
          {
            event: 'identity.client_user.ban_failed',
            actorId: principal.userId,
            clientId: params.clientId,
            targetUserId: params.userId,
          },
          'identity.client_user.ban_failed',
        );
      }
      logger.info(
        {
          event: 'identity.client_user.updated',
          actorId: principal.userId,
          clientId: params.clientId,
          targetUserId: params.userId,
          fields: Object.keys(body).sort(),
        },
        'identity.client_user.updated',
      );
      return json(200, toClientUserDto(result.value.user));
    },
  );
}

export const updateClientUserHandler = createUpdateClientUserHandler();
