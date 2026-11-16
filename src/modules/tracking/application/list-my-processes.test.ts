import { describe, expect, it } from 'vitest';
import { ForbiddenError, ServiceUnavailableError } from '@/shared/kernel';
import { ceoPrincipal, clientPrincipal } from './client-fixtures';
import { createFakeClientProcessQueries } from './fake-client-process-queries';
import { listMyProcesses } from './list-my-processes';
import { myProcessFixture } from './my-process-fixtures';

const CLIENT_B = '00000000-0000-4000-8000-00000000000b';

const at = (minutes: number) => new Date(Date.UTC(2026, 0, 1, 0, minutes));
const idOf = (n: number) => `00000000-0000-4000-8000-0000000003${String(n).padStart(2, '0')}`;

/** Five processes of the client of `clientPrincipal` (newest first: 5, 4, 3, 2, 1) and two of B. */
const queries = () =>
  createFakeClientProcessQueries([
    ...[1, 2, 3, 4, 5].map((n) => ({
      clientId: clientPrincipal.clientId ?? '',
      process: myProcessFixture({
        id: idOf(n),
        title: `Processo ${n}`,
        createdAt: at(n),
        updatedAt: at(n),
        ...(n === 2 ? { status: 'cancelled' as const } : {}),
      }),
    })),
    ...[8, 9].map((n) => ({
      clientId: CLIENT_B,
      process: myProcessFixture({ id: idOf(n), title: `Do B ${n}`, createdAt: at(n) }),
    })),
  ]);

describe('listMyProcesses', () => {
  it('AC-20: lists the processes of the client of the session, newest first, with the current stage', async () => {
    const result = await listMyProcesses({ queries: queries() }, clientPrincipal, {
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
      totalStages: 3,
      completedStages: 0,
      currentStage: { position: 1, name: 'Fase 1' },
    });
    expect(result.value.next).toBeNull();
  });

  it('AC-09: the tenant is the one of the session, so the processes of another client are never listed', async () => {
    const fake = queries();

    const result = await listMyProcesses({ queries: fake }, clientPrincipal, {
      query: { limit: 50 },
    });

    expect(fake.calls).toEqual([`list:${clientPrincipal.clientId}`]);
    expect(result.ok && result.value.items.map((item) => item.id)).not.toContain(idOf(8));
    expect(result.ok && result.value.items.map((item) => item.id)).not.toContain(idOf(9));

    const other = await listMyProcesses(
      { queries: fake },
      { ...clientPrincipal, userId: '33333333-3333-4333-8333-333333333333', clientId: CLIENT_B },
      { query: { limit: 50 } },
    );
    expect(other.ok && other.value.items.map((item) => item.id)).toEqual([idOf(9), idOf(8)]);
  });

  it('a client with no process gets an empty page', async () => {
    const result = await listMyProcesses(
      { queries: createFakeClientProcessQueries([]) },
      clientPrincipal,
      {
        query: { limit: 50 },
      },
    );

    expect(result).toEqual({ ok: true, value: { items: [], next: null } });
  });

  it('pages with a keyset, repeating and skipping nothing', async () => {
    const fake = queries();
    const seen: string[] = [];
    let after: { createdAt: string; id: string } | undefined;

    for (let page = 0; page < 5; page += 1) {
      const result = await listMyProcesses({ queries: fake }, clientPrincipal, {
        query: { limit: 2, ...(after === undefined ? {} : { after }) },
      });
      if (!result.ok) throw new Error('the page must be listed');
      seen.push(...result.value.items.map((item) => item.id));
      if (result.value.next === null) break;
      after = result.value.next;
    }

    expect(seen).toEqual([idOf(5), idOf(4), idOf(3), idOf(2), idOf(1)]);
  });

  it('AC-21, E-07: a CEO is refused, and nothing is read', async () => {
    const fake = queries();

    const result = await listMyProcesses({ queries: fake }, ceoPrincipal, { query: { limit: 50 } });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(fake.calls).toEqual([]);
  });

  it('fails closed on a client with no tenant: Forbidden, and nothing is read', async () => {
    const fake = queries();

    const result = await listMyProcesses(
      { queries: fake },
      { ...clientPrincipal, clientId: null },
      { query: { limit: 50 } },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(fake.calls).toEqual([]);
  });

  it('E-21: lets an outage of the database through, for the pipeline to answer 503', async () => {
    const fake = queries();
    fake.failWithOutage();

    await expect(
      listMyProcesses({ queries: fake }, clientPrincipal, { query: { limit: 50 } }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
