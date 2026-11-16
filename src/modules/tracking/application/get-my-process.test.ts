import { describe, expect, it } from 'vitest';
import { ForbiddenError, NotFoundError, ServiceUnavailableError } from '@/shared/kernel';
import { ceoPrincipal, clientPrincipal } from './client-fixtures';
import { createFakeClientProcessQueries } from './fake-client-process-queries';
import { getMyProcess } from './get-my-process';
import { myProcessFixture } from './my-process-fixtures';

const CLIENT_B = '00000000-0000-4000-8000-00000000000b';
const OWN = '00000000-0000-4000-8000-0000000001a1';
const OTHERS = '00000000-0000-4000-8000-0000000001b1';
const UNKNOWN = '00000000-0000-4000-8000-00000000dead';

const queries = () =>
  createFakeClientProcessQueries([
    {
      clientId: clientPrincipal.clientId ?? '',
      process: myProcessFixture({ id: OWN, statuses: ['completed', 'in_progress', 'pending'] }),
    },
    { clientId: CLIENT_B, process: myProcessFixture({ id: OTHERS, title: 'Do B' }) },
  ]);

describe('getMyProcess', () => {
  it('AC-20: returns the own process with its stages in order', async () => {
    const result = await getMyProcess({ queries: queries() }, clientPrincipal, { processId: OWN });

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
    const fake = queries();

    const foreign = await getMyProcess({ queries: fake }, clientPrincipal, { processId: OTHERS });
    const unknown = await getMyProcess({ queries: fake }, clientPrincipal, { processId: UNKNOWN });

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
    const fake = queries();

    await getMyProcess({ queries: fake }, clientPrincipal, { processId: OTHERS });
    const other = await getMyProcess(
      { queries: fake },
      { ...clientPrincipal, clientId: CLIENT_B },
      { processId: OTHERS },
    );

    expect(fake.calls).toEqual([
      `find:${clientPrincipal.clientId}:${OTHERS}`,
      `find:${CLIENT_B}:${OTHERS}`,
    ]);
    expect(other.ok && other.value.title).toBe('Do B');
  });

  it('AC-21, E-07: a CEO is refused, and nothing is read', async () => {
    const fake = queries();

    const result = await getMyProcess({ queries: fake }, ceoPrincipal, { processId: OWN });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(fake.calls).toEqual([]);
  });

  it('fails closed on a client with no tenant: Forbidden, and nothing is read', async () => {
    const fake = queries();

    const result = await getMyProcess(
      { queries: fake },
      { ...clientPrincipal, clientId: null },
      { processId: OWN },
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
      getMyProcess({ queries: fake }, clientPrincipal, { processId: OWN }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
