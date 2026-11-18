import { describe, expect, it } from 'vitest';
import { ForbiddenError, NotFoundError, ServiceUnavailableError } from '@/shared/kernel';
import { ClientArchivedError, ProcessNotActiveError, StaleStageError } from '../domain/errors';
import { invariantViolations } from '../domain/process';
import { approveCurrentStage } from './approve-current-stage';
import { ceoPrincipal, clientPrincipal } from './client-fixtures';
import { createFakeProcessRepository, FAKE_APPROVER } from './fake-process-repository';
import { CLIENT_A, processFixture, stageIdOf } from './process-fixtures';

const PROCESS = processFixture();
const ARCHIVED = { id: '00000000-0000-4000-8000-00000000000b', name: 'Cliente B', archived: true };

const repository = (process = PROCESS) =>
  createFakeProcessRepository({ clients: [CLIENT_A], processes: [process] });

describe('approveCurrentStage', () => {
  it('AC-16: completes the current stage with the approval and starts the next one', async () => {
    const processes = repository();

    const result = await approveCurrentStage({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      expectedStageId: stageIdOf(1),
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).toMatchObject({ status: 'active', version: 2, completedAt: null });
    expect(result.value.stages.map((stage) => stage.status)).toEqual([
      'completed',
      'in_progress',
      'pending',
    ]);
    expect(result.value.stages[0]?.approval?.approvedBy).toEqual({
      id: FAKE_APPROVER.userId,
      displayName: FAKE_APPROVER.displayName,
    });
    expect(result.value.stages[1]?.startedAt).toBeInstanceOf(Date);
    expect(invariantViolations(result.value)).toEqual([]);
    expect(processes.stored()).toEqual([result.value]);
  });

  it('AC-18: approving the last stage completes the process, and approving again is ProcessNotActiveError', async () => {
    const processes = repository(
      processFixture({ statuses: ['completed', 'completed', 'in_progress'] }),
    );

    const last = await approveCurrentStage({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      expectedStageId: stageIdOf(3),
    });
    expect(last.ok).toBe(true);
    if (!last.ok) return;
    expect(last.value).toMatchObject({ status: 'completed', version: 2 });
    expect(last.value.completedAt).toBeInstanceOf(Date);
    expect(last.value.stages.every((stage) => stage.status === 'completed')).toBe(true);

    const again = await approveCurrentStage({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      expectedStageId: stageIdOf(3),
    });
    expect(again.ok).toBe(false);
    if (!again.ok) expect(again.error).toBeInstanceOf(ProcessNotActiveError);
  });

  it('E-04: a process with a single stage is completed by the first approval', async () => {
    const processes = repository(processFixture({ statuses: ['in_progress'] }));

    const result = await approveCurrentStage({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      expectedStageId: stageIdOf(1),
    });

    expect(result.ok && result.value).toMatchObject({ status: 'completed', version: 2 });
  });

  it('E-01, E-02: a stage that is not the current one is StaleStageError carrying the current id, and nothing changes', async () => {
    const processes = repository();
    const first = await approveCurrentStage({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      expectedStageId: stageIdOf(1),
    });
    expect(first.ok).toBe(true);
    const stored = processes.stored();

    // the retry of the approval that was saved, a future stage and a stage that does not exist
    for (const expectedStageId of [
      stageIdOf(1),
      stageIdOf(3),
      '00000000-0000-4000-8000-00000000dead',
    ]) {
      const result = await approveCurrentStage({ processes }, ceoPrincipal, {
        processId: PROCESS.id,
        expectedStageId,
      });
      expect(result.ok).toBe(false);
      if (result.ok) continue;
      expect(result.error).toBeInstanceOf(StaleStageError);
      expect(result.error.extensions).toEqual({ currentStageId: stageIdOf(2) });
    }
    expect(processes.stored()).toEqual(stored);
  });

  it('E-03: a completed or cancelled process is ProcessNotActiveError, even with a stale stage id', async () => {
    const completed = processFixture({
      statuses: ['completed', 'completed'],
      status: 'completed',
      completedAt: new Date('2026-01-02T00:00:00.000Z'),
    });
    const cancelled = processFixture({
      id: '00000000-0000-4000-8000-0000000001a2',
      status: 'cancelled',
      cancelledAt: new Date('2026-01-02T00:00:00.000Z'),
    });
    const processes = createFakeProcessRepository({
      clients: [CLIENT_A],
      processes: [completed, cancelled],
    });

    for (const [processId, expectedStageId] of [
      [completed.id, stageIdOf(2)],
      [completed.id, '00000000-0000-4000-8000-00000000dead'],
      [cancelled.id, stageIdOf(1)],
      [cancelled.id, stageIdOf(2)],
    ] as const) {
      const result = await approveCurrentStage({ processes }, ceoPrincipal, {
        processId,
        expectedStageId,
      });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error).toBeInstanceOf(ProcessNotActiveError);
    }
    expect(processes.stored()).toEqual([completed, cancelled]);
  });

  it.each([
    ['an active process', { statuses: ['in_progress', 'pending'] as const }],
    [
      'a process that is already completed',
      {
        status: 'completed' as const,
        statuses: ['completed'] as const,
        completedAt: new Date('2026-01-02T00:00:00.000Z'),
      },
    ],
    [
      'a cancelled process',
      {
        status: 'cancelled' as const,
        statuses: ['in_progress'] as const,
        cancelledAt: new Date('2026-01-02T00:00:00.000Z'),
      },
    ],
  ])(
    'E-99, F-87: %s of an archived client is ClientArchivedError, whatever the stage asked for',
    async (_label, state) => {
      const frozen = processFixture({ clientId: ARCHIVED.id, client: ARCHIVED, ...state });
      const processes = createFakeProcessRepository({ clients: [ARCHIVED], processes: [frozen] });

      for (const expectedStageId of [
        stageIdOf(1),
        stageIdOf(2),
        '00000000-0000-4000-8000-0000000002ff',
      ]) {
        const result = await approveCurrentStage({ processes }, ceoPrincipal, {
          processId: frozen.id,
          expectedStageId,
        });

        expect(!result.ok && result.error).toBeInstanceOf(ClientArchivedError);
      }
      expect(processes.stored()).toEqual([frozen]);
    },
  );

  it('F-87: reading is not frozen, and an unknown process of an archived client is still NotFoundError', async () => {
    const frozen = processFixture({ clientId: ARCHIVED.id, client: ARCHIVED });
    const processes = createFakeProcessRepository({ clients: [ARCHIVED], processes: [frozen] });

    expect(await processes.find(frozen.id)).toEqual(frozen);
    const result = await approveCurrentStage({ processes }, ceoPrincipal, {
      processId: '00000000-0000-4000-8000-00000000dead',
      expectedStageId: stageIdOf(1),
    });
    expect(!result.ok && result.error).toBeInstanceOf(NotFoundError);
  });

  it('an unknown process is NotFoundError (404)', async () => {
    const processes = repository();

    const result = await approveCurrentStage({ processes }, ceoPrincipal, {
      processId: '00000000-0000-4000-8000-00000000dead',
      expectedStageId: stageIdOf(1),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(NotFoundError);
  });

  it('SEC-04: a client user is refused before the repository is touched', async () => {
    const processes = repository();

    const result = await approveCurrentStage({ processes }, clientPrincipal, {
      processId: PROCESS.id,
      expectedStageId: stageIdOf(1),
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
    expect(processes.calls).toEqual([]);
  });

  it('passes on a refusal of the database as it is, and changes nothing', async () => {
    const processes = repository();
    processes.refuseWrites(new ForbiddenError('denied'));

    const result = await approveCurrentStage({ processes }, ceoPrincipal, {
      processId: PROCESS.id,
      expectedStageId: stageIdOf(1),
    });

    expect(result.ok).toBe(false);
    expect(processes.stored()).toEqual([PROCESS]);
  });

  it('E-21: an outage is thrown', async () => {
    const processes = repository();
    processes.failWithOutage();

    await expect(
      approveCurrentStage({ processes }, ceoPrincipal, {
        processId: PROCESS.id,
        expectedStageId: stageIdOf(1),
      }),
    ).rejects.toBeInstanceOf(ServiceUnavailableError);
  });
});
