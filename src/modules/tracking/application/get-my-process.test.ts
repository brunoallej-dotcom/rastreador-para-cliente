import { describe, expect, it } from 'vitest';
import { ForbiddenError, NotFoundError, ServiceUnavailableError } from '@/shared/kernel';
import { ceoPrincipal, clientPrincipal } from './client-fixtures';
import { createFakeClientProcessQueries } from './fake-client-process-queries';
import { getMyProcess } from './get-my-process';
import { myProcessFixture, panelLoggerFixture } from './my-process-fixtures';

const CLIENT_B = '00000000-0000-4000-8000-00000000000b';
const OWN = '00000000-0000-4000-8000-0000000001a1';
const OTHERS = '00000000-0000-4000-8000-0000000001b1';
const UNKNOWN = '00000000-0000-4000-8000-00000000dead';

const queries = () =>
  createFakeClientProcessQueries([
    {
      clientId: clientPrincipal.clientId ?? '',
      process: myProcessFixture({
        id: OWN,
        title: 'Titulo do A',
        statuses: ['completed', 'in_progress', 'pending'],
      }),
    },
    { clientId: CLIENT_B, process: myProcessFixture({ id: OTHERS, title: 'Do B' }) },
  ]);

/** The use case with a recording logger: `log` says what was logged. */
function setup() {
  const fake = queries();
  const log = panelLoggerFixture();
  return { fake, log, deps: { queries: fake, logger: log.logger } };
}

describe('getMyProcess', () => {
  it('AC-20: returns the own process with its stages in order', async () => {
    const { deps } = setup();

    const result = await getMyProcess(deps, clientPrincipal, { processId: OWN });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.id).toBe(OWN);
    expect(result.value.stages.map((stage) => stage.status)).toEqual([
      'completed',
      'in_progress',
      'pending',
    ]);
    expect(result.value.currentStage).toEqual({ position: 2, name: 'Fase 2' });
  });

  it('AC-09, E-05: the process of another client and one that does not exist are the same NotFound', async () => {
    const { deps } = setup();

    const foreign = await getMyProcess(deps, clientPrincipal, { processId: OTHERS });
    const unknown = await getMyProcess(deps, clientPrincipal, { processId: UNKNOWN });

    expect(foreign.ok).toBe(false);
    expect(unknown.ok).toBe(false);
    if (foreign.ok || unknown.ok) return;
    expect(foreign.error).toBeInstanceOf(NotFoundError);
    expect(unknown.error).toBeInstanceOf(NotFoundError);
    expect(foreign.error.message).toBe(unknown.error.message);
    expect(foreign.error.detail).toBe(unknown.error.detail);
    expect(foreign.error.extensions).toEqual(unknown.error.extensions);
  });

  it('AC-09: asks for the process with the tenant of the session, and the other client sees its own only', async () => {
    const { fake, deps } = setup();

    await getMyProcess(deps, clientPrincipal, { processId: OTHERS });
    const other = await getMyProcess(
      deps,
      { ...clientPrincipal, clientId: CLIENT_B },
      { processId: OTHERS },
    );

    expect(fake.calls).toEqual([
      `find:${clientPrincipal.clientId}:${OTHERS}`,
      `find:${CLIENT_B}:${OTHERS}`,
    ]);
    expect(other.ok && other.value.title).toBe('Do B');
  });

  it('F-99: a successful read leaves a trail with the process id only; a 404 leaves none', async () => {
    const { deps, log } = setup();

    await getMyProcess(deps, clientPrincipal, { processId: OTHERS });
    await getMyProcess(deps, clientPrincipal, { processId: UNKNOWN });
    expect(log.info).not.toHaveBeenCalled();

    await getMyProcess(deps, clientPrincipal, { processId: OWN });

    expect(log.info.mock.calls).toEqual([
      [{ event: 'tracking.client_panel_read', processId: OWN }, 'tracking.client_panel_read'],
    ]);
    const logged = JSON.stringify(log.info.mock.calls);
    expect(logged).not.toContain('Titulo do A');
    expect(logged).not.toContain('Fase');
    expect(logged).not.toContain(clientPrincipal.clientId ?? 'never');
    expect(log.error).not.toHaveBeenCalled();
  });

  it('AC-21, E-07: a CEO is refused, nothing is read, and the refusal is logged as a defect signal without PII', async () => {
    const { fake, deps, log } = setup();

    const result = await getMyProcess(deps, ceoPrincipal, { processId: OWN });

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
  });

  it('fails closed on a client with no tenant: Forbidden, nothing is read, and the signal is logged', async () => {
    const { fake, deps, log } = setup();

    const result = await getMyProcess(
      deps,
      { ...clientPrincipal, clientId: null },
      { processId: OWN },
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

    await expect(getMyProcess(deps, clientPrincipal, { processId: OWN })).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
    expect(log.info).not.toHaveBeenCalled();
  });
});
