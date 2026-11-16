import { describe, expect, it } from 'vitest';
import { ForbiddenError, NotFoundError, ServiceUnavailableError } from '@/shared/kernel';
import { ceoPrincipal, clientPrincipal } from './client-fixtures';
import { createFakeProcessRepository } from './fake-process-repository';
import { getProcess } from './get-process';
import { CLIENT_A, processFixture } from './process-fixtures';

const PROCESS = processFixture();

const repository = () => createFakeProcessRepository({ clients: [CLIENT_A], processes: [PROCESS] });

describe('getProcess', () => {
  it('AC-15: a CEO reads the process with its stages and its client', async () => {
    const processes = repository();

    const result = await getProcess({ processes }, ceoPrincipal, { processId: PROCESS.id });

    expect(result.ok && result.value).toEqual(PROCESS);
  });

  it('an unknown process is NotFoundError (404)', async () => {
    const processes = repository();

    const result = await getProcess({ processes }, ceoPrincipal, {
      processId: '00000000-0000-4000-8000-00000000dead',
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(NotFoundError);
  });

  it('SEC-04: a client user is refused before the repository is touched', async () => {
    const processes = repository();

    const result = await getProcess({ processes }, clientPrincipal, { processId: PROCESS.id });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(processes.calls).toEqual([]);
  });

  it('E-21: an outage is thrown', async () => {
    const processes = repository();
    processes.failWithOutage();

    await expect(
      getProcess({ processes }, ceoPrincipal, { processId: PROCESS.id }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
