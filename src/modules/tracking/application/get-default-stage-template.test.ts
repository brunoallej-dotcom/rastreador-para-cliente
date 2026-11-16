import { describe, expect, it } from 'vitest';
import { ForbiddenError, ServiceUnavailableError } from '@/shared/kernel';
import { ceoPrincipal, clientPrincipal } from './client-fixtures';
import { createFakeProcessRepository, FAKE_TEMPLATE } from './fake-process-repository';
import { getDefaultStageTemplate } from './get-default-stage-template';

describe('getDefaultStageTemplate', () => {
  it('AC-15: a CEO reads the stages a new process gets, in order', async () => {
    const processes = createFakeProcessRepository();

    const result = await getDefaultStageTemplate({ processes }, ceoPrincipal);

    expect(result.ok && result.value).toEqual(FAKE_TEMPLATE);
  });

  it('SEC-04: a client user is refused before the repository is touched', async () => {
    const processes = createFakeProcessRepository();

    const result = await getDefaultStageTemplate({ processes }, clientPrincipal);

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(processes.calls).toEqual([]);
  });

  it('E-21: an outage is thrown', async () => {
    const processes = createFakeProcessRepository();
    processes.failWithOutage();

    await expect(getDefaultStageTemplate({ processes }, ceoPrincipal)).rejects.toBeInstanceOf(
      ServiceUnavailableError,
    );
  });
});
