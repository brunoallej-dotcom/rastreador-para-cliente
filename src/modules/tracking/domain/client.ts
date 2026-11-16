import { err, ok, ValidationError, type Result } from '@/shared/kernel';

/** `clients.name` has 1 to 160 characters after trimming (spec §4.1, contract `CreateClientRequest`). */
export const CLIENT_NAME_MAX_LENGTH = 160;

/**
 * A client: the company that hired a delivery, and the tenant of its logins and processes.
 * Read model of the CEO panel: the two counters come from the client's processes.
 */
export type Client = {
  readonly id: string;
  readonly name: string;
  /** `null` while the client is active. */
  readonly archivedAt: Date | null;
  /** Processes with status `active`. */
  readonly activeProcessCount: number;
  /** Processes in any status. */
  readonly processCount: number;
  readonly createdAt: Date;
  readonly updatedAt: Date;
};

/** An archived client takes no new processes and no new logins (Q-08: existing logins stay on). */
export function isArchived(client: Pick<Client, 'archivedAt'>): boolean {
  return client.archivedAt !== null;
}

/**
 * What `PATCH /admin/clients/{clientId}` may change. A missing field is left alone; `archived: true`
 * archives and `archived: false` brings the client back.
 */
export type ClientPatch = {
  readonly name?: string;
  readonly archived?: boolean;
};

/**
 * A patch must change something (contract: `UpdateClientRequest.minProperties: 1`). The database
 * function refuses the empty patch too; this check answers 400 before the round trip.
 */
export function requireChange(patch: ClientPatch): Result<ClientPatch, ValidationError> {
  if (patch.name === undefined && patch.archived === undefined) {
    return err(
      new ValidationError('the patch names no field', [
        { path: 'body', message: 'Must name at least one field to change' },
      ]),
    );
  }
  return ok(patch);
}

/**
 * Where a page of the client list stops: the `created_at` and `id` of its last row, the keyset of
 * the order the list uses (newest first, `id` breaking ties). `createdAt` is the exact text the
 * database sent (microsecond precision): a `Date` would round it to milliseconds, and the next page
 * would then repeat or skip the rows that share that millisecond.
 */
export type ClientListPosition = {
  readonly createdAt: string;
  readonly id: string;
};

export type ClientListQuery = {
  readonly limit: number;
  /** The page starts right after this position; absent for the first page. */
  readonly after?: ClientListPosition;
  readonly includeArchived: boolean;
};

/** `next` is `null` on the last page. */
export type ClientPage = {
  readonly items: readonly Client[];
  readonly next: ClientListPosition | null;
};
