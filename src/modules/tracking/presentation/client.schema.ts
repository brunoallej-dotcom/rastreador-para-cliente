import { z } from 'zod';
import { pageQueryShape, visibleText } from '@/shared/http';
import { CLIENT_NAME_MAX_LENGTH } from '../domain/client';

/** The text of a client name: NFC, trimmed, 1 to 160 visible characters (E-30), as the contract. */
const clientName = () => visibleText({ min: 1, max: CLIENT_NAME_MAX_LENGTH });

/** `ClientId` path parameter: a UUID. A malformed id is a 400, never a 404 (E-06). */
export const clientIdParamsSchema = z.object({ clientId: z.uuid() }).strict();

/**
 * Query of `GET /admin/clients`: `limit` and `cursor` (the shared page query) and `includeArchived`.
 * `includeArchived` is the text `true` or `false` only (default `false`); anything else is a 400.
 */
export const listClientsQuerySchema = z
  .object({
    ...pageQueryShape,
    includeArchived: z
      .enum(['true', 'false'])
      .transform((value) => value === 'true')
      .default(false),
  })
  .strict();

/** `CreateClientRequest` (contract). `.strict()`: any other field is a 400 (mass assignment). */
export const createClientBodySchema = z.object({ name: clientName() }).strict();

/**
 * `UpdateClientRequest` (contract): `name` and/or `archived`, and at least one of them
 * (`minProperties: 1`). `.strict()`: any other field, a `clientId` included, is a 400.
 */
export const updateClientBodySchema = z
  .object({ name: clientName().optional(), archived: z.boolean().optional() })
  .strict()
  .refine((body) => body.name !== undefined || body.archived !== undefined, {
    error: 'Must name at least one field to change',
  });
