import { getRequestSupabase } from '@/shared/db/server-client';
import { json, withRoute, type WithRoute } from '@/shared/http';
import { provisionClientUser } from '../application/provision-client-user';
import {
  ClientUserProvisionOrphanedError,
  ClientUserProvisionRolledBackError,
} from '../domain/client-user-errors';
import { createSupabaseAccountAdminGateway } from '../infrastructure/supabase-account-admin-gateway';
import { createSupabaseAccountRepository } from '../infrastructure/supabase-account-repository';
import { createTrackingClientStatusDirectory } from '../infrastructure/tracking-client-directory';
import { toProvisionedClientUserDto } from './client-user.dto';
import { CLIENT_USER_ADMIN_RULE } from './client-user-rate-limits';
import { clientIdParamsSchema, provisionClientUserBodySchema } from './client-user.schema';

const CREATED = 201;

/**
 * `POST /admin/clients/{clientId}/users` (operationId `provisionClientUser`). Policy equal to the
 * contract: role ceo only, `allowPending: []`, user 20 / hour in the `client-user-admin` counter that
 * the password reset shares. Answers 201 with the login and its temporary password, which is in no
 * other place: not in a log (the logger redacts the key, and no line here carries the value), not in
 * the database, not in an error.
 *
 * The tenant is the path's `clientId` and nothing in the body can change it (`.strict()`).
 *
 * `route` is `withRoute` in production; tests pass a pipeline wired to fakes.
 */
export function createProvisionClientUserHandler(route: WithRoute = withRoute) {
  return route(
    {
      access: 'authenticated',
      roles: ['ceo'],
      allowPending: [],
      rateLimit: [CLIENT_USER_ADMIN_RULE],
      params: clientIdParamsSchema,
      body: provisionClientUserBodySchema,
    },
    async ({ request, requestId, cookies, logger, principal, params, body }) => {
      const supabase = getRequestSupabase({ request, cookies, requestId });

      let result: Awaited<ReturnType<typeof provisionClientUser>>;
      try {
        result = await provisionClientUser(
          {
            clients: createTrackingClientStatusDirectory(supabase),
            users: createSupabaseAccountRepository(supabase, { logger }),
            accounts: createSupabaseAccountAdminGateway(),
          },
          principal,
          { clientId: params.clientId, email: body.email, displayName: body.displayName },
        );
      } catch (error) {
        if (error instanceof ClientUserProvisionOrphanedError) {
          // An account nobody was given the password of is left behind (E-23): a person must find this.
          logger.error(
            {
              event: 'identity.client_user.provision_orphaned',
              actorId: principal.userId,
              clientId: params.clientId,
              targetUserId: error.userId,
            },
            'identity.client_user.provision_orphaned',
          );
        } else if (error instanceof ClientUserProvisionRolledBackError) {
          logger.error(
            {
              event: 'identity.client_user.provision_rolled_back',
              actorId: principal.userId,
              clientId: params.clientId,
            },
            'identity.client_user.provision_rolled_back',
          );
        }
        throw error;
      }
      if (!result.ok) return result.error;

      logger.info(
        {
          event: 'identity.client_user.provisioned',
          actorId: principal.userId,
          clientId: params.clientId,
          targetUserId: result.value.user.id,
        },
        'identity.client_user.provisioned',
      );
      return json(CREATED, toProvisionedClientUserDto(result.value));
    },
  );
}

export const provisionClientUserHandler = createProvisionClientUserHandler();
