import { describe, expect, it } from 'vitest';
import { ForbiddenError, ServiceUnavailableError } from '@/shared/kernel';
import type { Client, ClientListPosition } from '../domain/client';
import { ceoPrincipal, clientFixture, clientPrincipal } from './client-fixtures';
import { createFakeClientRepository } from './fake-client-repository';
import { listClients } from './list-clients';

const id = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const at = (minute: number) => new Date(Date.UTC(2026, 0, 1, 0, minute));

/** Five clients: 1 is the oldest and 5 the newest; 2 is archived; 4 and 5 share an instant. */
const stored: readonly Client[] = [
  clientFixture({ id: id(1), name: 'Um', createdAt: at(1) }),
  clientFixture({ id: id(2), name: 'Dois', createdAt: at(2), archivedAt: at(10) }),
  clientFixture({ id: id(3), name: 'Três', createdAt: at(3) }),
  clientFixture({ id: id(5), name: 'Cinco', createdAt: at(4) }),
  clientFixture({ id: id(4), name: 'Quatro', createdAt: at(4) }),
];

const names = (items: readonly Client[]) => items.map((client) => client.name);

describe('listClients', () => {
  it('AC-11: lists active clients, newest first, id breaking the tie', async () => {
    const clients = createFakeClientRepository(stored);

    const result = await listClients({ clients }, ceoPrincipal, {
      limit: 50,
      includeArchived: false,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(names(result.value.items)).toEqual(['Quatro', 'Cinco', 'Três', 'Um']);
    expect(result.value.next).toBeNull();
  });

  it('AC-11: includeArchived brings the archived client back', async () => {
    const clients = createFakeClientRepository(stored);

    const result = await listClients({ clients }, ceoPrincipal, {
      limit: 50,
      includeArchived: true,
    });

    expect(result.ok).toBe(true);
    if (result.ok)
      expect(names(result.value.items)).toEqual(['Quatro', 'Cinco', 'Três', 'Dois', 'Um']);
  });

  it('AC-11: pages by keyset without repeating or skipping a row, even on a shared instant', async () => {
    const clients = createFakeClientRepository(stored);
    const seen: string[] = [];
    let after: ClientListPosition | undefined;

    for (let page = 0; page < 10; page += 1) {
      const result = await listClients({ clients }, ceoPrincipal, {
        limit: 1,
        includeArchived: true,
        ...(after === undefined ? {} : { after }),
      });
      expect(result.ok).toBe(true);
      if (!result.ok) return;
      seen.push(...names(result.value.items));
      if (result.value.next === null) break;
      after = result.value.next;
    }

    expect(seen).toEqual(['Quatro', 'Cinco', 'Três', 'Dois', 'Um']);
  });

  it('SEC-04: a client user is refused before the repository is touched', async () => {
    const clients = createFakeClientRepository(stored);

    const result = await listClients({ clients }, clientPrincipal, {
      limit: 50,
      includeArchived: false,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(clients.calls).toEqual([]);
  });

  it('E-21: an outage is thrown', async () => {
    const clients = createFakeClientRepository(stored);
    clients.failWithOutage();

    await expect(
      listClients({ clients }, ceoPrincipal, { limit: 50, includeArchived: false }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
