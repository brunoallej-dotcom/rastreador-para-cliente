import { isArchived, type Client, type ClientPage } from '../domain/client';
import { encodeClientCursor } from './client.cursor';

/** `ClientSummary` of the contract. Explicit fields, nothing spread from a row. */
export type ClientSummaryDto = {
  readonly id: string;
  readonly name: string;
  readonly archived: boolean;
  readonly archivedAt: string | null;
  readonly activeProcessCount: number;
  readonly createdAt: string;
  readonly updatedAt: string;
};

/** `ClientDetail` of the contract: the summary plus the total process count. */
export type ClientDetailDto = ClientSummaryDto & { readonly processCount: number };

/** `ClientList` of the contract. */
export type ClientListDto = {
  readonly items: readonly ClientSummaryDto[];
  readonly nextCursor: string | null;
};

export function toClientSummaryDto(client: Client): ClientSummaryDto {
  return {
    id: client.id,
    name: client.name,
    archived: isArchived(client),
    archivedAt: client.archivedAt === null ? null : client.archivedAt.toISOString(),
    activeProcessCount: client.activeProcessCount,
    createdAt: client.createdAt.toISOString(),
    updatedAt: client.updatedAt.toISOString(),
  };
}

export function toClientDetailDto(client: Client): ClientDetailDto {
  return {
    id: client.id,
    name: client.name,
    archived: isArchived(client),
    archivedAt: client.archivedAt === null ? null : client.archivedAt.toISOString(),
    activeProcessCount: client.activeProcessCount,
    processCount: client.processCount,
    createdAt: client.createdAt.toISOString(),
    updatedAt: client.updatedAt.toISOString(),
  };
}

export function toClientListDto(page: ClientPage): ClientListDto {
  return {
    items: page.items.map(toClientSummaryDto),
    nextCursor: page.next === null ? null : encodeClientCursor(page.next),
  };
}
