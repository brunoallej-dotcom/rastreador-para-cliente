import { describe, expect, it } from 'vitest';
import { ForbiddenError, ServiceUnavailableError } from '@/shared/kernel';
import { ceoPrincipal, clientPrincipal } from './client-fixtures';
import { createFakeClientProcessQueries } from './fake-client-process-queries';
import { listMyProcesses } from './list-my-processes';
import { myProcessFixture, panelLoggerFixture } from './my-process-fixtures';

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

/** The use case with a recording logger: `log` says what was logged. */
function setup(fake = queries()) {
  const log = panelLoggerFixture();
  return { fake, log, deps: { queries: fake, logger: log.logger } };
}

describe('listMyProcesses', () => {
  it('AC-20: lists the processes of the client of the session, newest first, with the current stage', async () => {
    const { deps } = setup();

    const result = await listMyProcesses(deps, clientPrincipal, { query: { limit: 50 } });

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
    const { fake, deps } = setup();

    const result = await listMyProcesses(deps, clientPrincipal, { query: { limit: 50 } });

    expect(fake.calls).toEqual([`list:${clientPrincipal.clientId}`]);
    expect(result.ok && result.value.items.map((item) => item.id)).not.toContain(idOf(8));
    expect(result.ok && result.value.items.map((item) => item.id)).not.toContain(idOf(9));

    const other = await listMyProcesses(
      deps,
      { ...clientPrincipal, userId: '33333333-3333-4333-8333-333333333333', clientId: CLIENT_B },
      { query: { limit: 50 } },
    );
    expect(other.ok && other.value.items.map((item) => item.id)).toEqual([idOf(9), idOf(8)]);
  });

  it('a client with no process gets an empty page', async () => {
    const { deps } = setup(createFakeClientProcessQueries([]));

    const result = await listMyProcesses(deps, clientPrincipal, { query: { limit: 50 } });

    expect(result).toEqual({ ok: true, value: { items: [], next: null } });
  });

  it('pages with a keyset, repeating and skipping nothing', async () => {
    const { deps } = setup();
    const seen: string[] = [];
    let after: { createdAt: string; id: string } | undefined;

    for (let page = 0; page < 5; page += 1) {
      const result = await listMyProcesses(deps, clientPrincipal, {
        query: { limit: 2, ...(after === undefined ? {} : { after }) },
      });
      if (!result.ok) throw new Error('the page must be listed');
      seen.push(...result.value.items.map((item) => item.id));
      if (result.value.next === null) break;
      after = result.value.next;
    }

    expect(seen).toEqual([idOf(5), idOf(4), idOf(3), idOf(2), idOf(1)]);
  });

  it('F-99: leaves a trail of the page: how many processes, and whether it was a later page, and nothing else', async () => {
    const { deps, log } = setup();

    const first = await listMyProcesses(deps, clientPrincipal, { query: { limit: 2 } });
    if (!first.ok || first.value.next === null) throw new Error('there is a second page');
    await listMyProcesses(deps, clientPrincipal, {
      query: { limit: 2, after: first.value.next },
    });

    expect(log.info.mock.calls).toEqual([
      [
        { event: 'tracking.client_panel_list', count: 2, paged: false },
        'tracking.client_panel_list',
      ],
      [
        { event: 'tracking.client_panel_list', count: 2, paged: true },
        'tracking.client_panel_list',
      ],
    ]);
    // no title, no process id, no client id in what was logged
    const logged = JSON.stringify(log.info.mock.calls);
    expect(logged).not.toContain('Processo');
    expect(logged).not.toContain(idOf(5));
    expect(logged).not.toContain(clientPrincipal.clientId ?? 'never');
    expect(log.error).not.toHaveBeenCalled();
  });

  it('AC-21, E-07: a CEO is refused, nothing is read, and the refusal is logged as a defect signal without PII', async () => {
    const { fake, deps, log } = setup();

    const result = await listMyProcesses(deps, ceoPrincipal, { query: { limit: 50 } });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(fake.calls).toEqual([]);
    expect(log.error.mock.calls).toEqual([
      [
        { event: 'tracking.client_panel_role_guard', role: 'ceo', hasTenant: false },
        'tracking.client_panel_role_guard',
      ],
    ]);
    expect(log.info).not.toHaveBeenCalled();
    expect(JSON.stringify(log.error.mock.calls)).not.toContain(ceoPrincipal.userId);
  });

  it('fails closed on a client with no tenant: Forbidden, nothing is read, and the signal says a role was there but no tenant', async () => {
    const { fake, deps, log } = setup();

    const result = await listMyProcesses(
      deps,
      { ...clientPrincipal, clientId: null },
      { query: { limit: 50 } },
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(fake.calls).toEqual([]);
    expect(log.error.mock.calls).toEqual([
      [
        { event: 'tracking.client_panel_role_guard', role: 'client', hasTenant: false },
        'tracking.client_panel_role_guard',
      ],
    ]);
  });

  it('E-21: lets an outage of the database through, for the pipeline to answer 503, and logs no trail', async () => {
    const { fake, deps, log } = setup();
    fake.failWithOutage();

    await expect(
      listMyProcesses(deps, clientPrincipal, { query: { limit: 50 } }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
    expect(log.info).not.toHaveBeenCalled();
  });
});
