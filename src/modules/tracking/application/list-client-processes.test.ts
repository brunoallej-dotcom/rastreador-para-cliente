import { describe, expect, it } from 'vitest';
import { ForbiddenError, NotFoundError, ServiceUnavailableError } from '@/shared/kernel';
import { ceoPrincipal, clientPrincipal } from './client-fixtures';
import { createFakeProcessRepository } from './fake-process-repository';
import { listClientProcesses } from './list-client-processes';
import { CLIENT_A, processFixture } from './process-fixtures';

const OTHER = { id: '00000000-0000-4000-8000-00000000000b', name: 'Cliente B' };

const at = (minutes: number) => new Date(Date.UTC(2026, 0, 1, 0, minutes));
const idOf = (n: number) => `00000000-0000-4000-8000-0000000003${String(n).padStart(2, '0')}`;

/** Five processes of A, newest first by id order: 5, 4, 3, 2, 1; plus one of B. */
const repository = () =>
  createFakeProcessRepository({
    clients: [CLIENT_A, OTHER],
    processes: [
      ...[1, 2, 3, 4, 5].map((n) =>
        processFixture({
          id: idOf(n),
          title: `Processo ${n}`,
          createdAt: at(n),
          updatedAt: at(n),
          ...(n === 2 ? { status: 'cancelled' as const, cancelledAt: at(n) } : {}),
        }),
      ),
      processFixture({ id: idOf(9), clientId: OTHER.id, client: OTHER, createdAt: at(9) }),
    ],
  });

describe('listClientProcesses', () => {
  it('AC-15: lists the processes of the client, newest first, with the current stage and progress', async () => {
    const processes = repository();

    const result = await listClientProcesses({ processes }, ceoPrincipal, {
      clientId: CLIENT_A.id,
      query: { limit: 50 },
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.items.map((item) => item.title)).toEqual([
      'Processo 5',
      'Processo 4',
      'Processo 3',
      'Processo 2',
      'Processo 1',
    ]);
    expect(result.value.items[0]).toMatchObject({
      clientId: CLIENT_A.id,
      totalStages: 3,
      completedStages: 0,
      currentStage: { position: 1 },
    });
    expect(result.value.next).toBeNull();
  });

  it('AC-15: never lists the processes of another client', async () => {
    const processes = repository();

    const result = await listClientProcesses({ processes }, ceoPrincipal, {
      clientId: OTHER.id,
      query: { limit: 50 },
    });

    expect(result.ok && result.value.items.map((item) => item.id)).toEqual([idOf(9)]);
  });

  it('pages with a keyset, repeating and skipping nothing', async () => {
    const processes = repository();
    const seen: string[] = [];
    let after: { createdAt: string; id: string } | undefined;

    for (let page = 0; page < 5; page += 1) {
      const result = await listClientProcesses({ processes }, ceoPrincipal, {
        clientId: CLIENT_A.id,
        query: { limit: 2, ...(after === undefined ? {} : { after }) },
      });
      if (!result.ok) throw new Error('the page must be listed');
      seen.push(...result.value.items.map((item) => item.id));
      if (result.value.next === null) break;
      after = result.value.next;
    }

    expect(seen).toEqual([idOf(5), idOf(4), idOf(3), idOf(2), idOf(1)]);
  });

  it('filters by status', async () => {
    const processes = repository();

    const result = await listClientProcesses({ processes }, ceoPrincipal, {
      clientId: CLIENT_A.id,
      query: { limit: 50, status: 'cancelled' },
    });

    expect(result.ok && result.value.items.map((item) => item.id)).toEqual([idOf(2)]);
  });

  it('a client with no process is an empty page, not a 404', async () => {
    const processes = createFakeProcessRepository({ clients: [CLIENT_A] });

    const result = await listClientProcesses({ processes }, ceoPrincipal, {
      clientId: CLIENT_A.id,
      query: { limit: 50 },
    });

    expect(result.ok && result.value).toEqual({ items: [], next: null });
  });

  it('an unknown client is NotFoundError (404)', async () => {
    const processes = repository();

    const result = await listClientProcesses({ processes }, ceoPrincipal, {
      clientId: '00000000-0000-4000-8000-00000000dead',
      query: { limit: 50 },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(NotFoundError);
  });

  it('SEC-04: a client user is refused before the repository is touched', async () => {
    const processes = repository();

    const result = await listClientProcesses({ processes }, clientPrincipal, {
      clientId: CLIENT_A.id,
      query: { limit: 50 },
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(processes.calls).toEqual([]);
  });

  it('E-21: an outage is thrown', async () => {
    const processes = repository();
    processes.failWithOutage();

    await expect(
      listClientProcesses({ processes }, ceoPrincipal, {
        clientId: CLIENT_A.id,
        query: { limit: 50 },
      }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
