import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { resetClientUserPassword } from '../application/reset-client-user-password';
import { ClientUserResetIncompleteError } from '../domain/client-user-errors';
import { createSupabaseAccountAdminGateway } from '../infrastructure/supabase-account-admin-gateway';
import { createSupabaseAccountRepository } from '../infrastructure/supabase-account-repository';
import { toTemporaryPasswordDto } from './client-user.dto';
import { CLIENT_USER_ADMIN_RULE } from './client-user-rate-limits';
import { clientUserParamsSchema } from './client-user.schema';

/**
 * `POST /admin/clients/{clientId}/users/{userId}/password-reset` (operationId
 * `resetClientUserPassword`). Policy equal to the contract: role ceo only, `allowPending: []`, user
 * 20 / hour in the `client-user-admin` counter that the provisioning shares. The route has no body: it
 * is not read, so a body (and a Content-Type) is simply ignored, as the contract says (no 400, 413 or
 * 415 for it). Answers 200 with the new temporary password, in no other place (see the provisioning).
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createResetClientUserPasswordHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [CLIENT_USER_ADMIN_RULE],
      params: clientUserParamsSchema,
    },
    async ({ request, requestId, cookies, logger, principal, params }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });

      let result: Awaited<ReturnType<typeof resetClientUserPassword>>;
      try {
        result = await resetClientUserPassword(
          {
            users: createSupabaseAccountRepository(supabase, { logger }),
            accounts: createSupabaseAccountAdminGateway(),
          },
          principal,
          { clientId: params.clientId, userId: params.userId },
        );
      } catch (error) {
        if (error instanceof ClientUserResetIncompleteError) {
          // The old password no longer works and nobody has the new one: a person must find this.
          // `failure` is a code and a status: why the database step failed, never what it said.
          logger.error(
            {
              event: 'identity.client_user.reset_incomplete',
              actorId: principal.userId,
              clientId: params.clientId,
              targetUserId: params.userId,
              failure: error.failure,
            },
            'identity.client_user.reset_incomplete',
          );
        }
        throw error;
      }
      if (!result.ok) return result.error;

      logger.info(
        {
          event: 'identity.client_user.password_reset',
          actorId: principal.userId,
          clientId: params.clientId,
          targetUserId: params.userId,
        },
        'identity.client_user.password_reset',
      );
      return json(200, toTemporaryPasswordDto(result.value.temporaryPassword));
    },
  );
}

export const resetClientUserPasswordHandler = createResetClientUserPasswordHandler();
