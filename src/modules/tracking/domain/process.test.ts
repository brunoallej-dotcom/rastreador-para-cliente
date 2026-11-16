import { describe, expect, it } from 'vitest';
import { ForbiddenError, ValidationError } from '@/shared/kernel';
import { ProcessNotActiveError, StaleStageError } from './errors';
import {
  applyProcessPatch,
  approveCurrentStage,
  completedStageCount,
  currentStageOf,
  invariantViolations,
  requireProcessChange,
  startProcess,
  summarize,
  type Approver,
  type Process,
} from './process';
import { MAX_STAGES_PER_PROCESS, type Stage, type StageInput, type StageStatus } from './stage';

const AT = new Date('2026-03-01T10:00:00.000Z');
const LATER = new Date('2026-03-02T10:00:00.000Z');
const CLIENT = { id: '00000000-0000-4000-8000-00000000000a', name: 'Cliente A' };
const CEO: Approver = {
  userId: '11111111-1111-4111-8111-111111111111',
  displayName: 'CEO Um',
  role: 'ceo',
  aal: 'aal2',
};

const stageId = (position: number) =>
  `00000000-0000-4000-8000-0000000002${String(position).padStart(2, '0')}`;

const inputs = (count: number): StageInput[] =>
  Array.from({ length: count }, (_value, index) => ({ name: `Fase ${index + 1}` }));

function started(count = 3, title = 'Processo A'): Process {
  let next = 0;
  const result = startProcess({
    id: '00000000-0000-4000-8000-0000000001a1',
    client: CLIENT,
    title,
    stages: inputs(count),
    at: AT,
    newStageId: () => stageId(++next),
  });
  if (!result.ok) throw new Error('the fixture process must start');
  return result.value;
}

/** The same process with its stages replaced, to build the broken snapshots the invariants name. */
const withStages = (process: Process, change: (stages: readonly Stage[]) => readonly Stage[]) => ({
  ...process,
  stages: change(process.stages),
});

const stageAt = (process: Process, position: number): Stage => {
  const stage = process.stages[position - 1];
  if (stage === undefined) throw new Error(`no stage at ${position}`);
  return stage;
};

const statusesOf = (process: Process): StageStatus[] => process.stages.map((stage) => stage.status);

const invariantsOf = (process: Process) =>
  [...new Set(invariantViolations(process).map((violation) => violation.invariant))].sort();

function approved(process: Process, at = LATER): Process {
  const current = currentStageOf(process);
  if (current === null) throw new Error('the fixture process has no current stage');
  const result = approveCurrentStage(process, { expectedStageId: current.id, approver: CEO, at });
  if (!result.ok) throw new Error('the fixture approval must pass');
  return result.value;
}

describe('startProcess', () => {
  it('AC-15, I2: starts active at version 1, with the first stage in progress and the rest pending', () => {
    const process = started(3);

    expect(process).toMatchObject({
      status: 'active',
      version: 1,
      completedAt: null,
      cancelledAt: null,
      clientId: CLIENT.id,
      client: CLIENT,
      createdAt: AT,
      updatedAt: AT,
    });
    expect(statusesOf(process)).toEqual(['in_progress', 'pending', 'pending']);
    expect(stageAt(process, 1)).toMatchObject({ startedAt: AT, completedAt: null, approval: null });
    expect(stageAt(process, 2)).toMatchObject({ startedAt: null, completedAt: null });
    expect(invariantViolations(process)).toEqual([]);
  });

  it('I1: gives the stages the positions 1 to n, in the order sent, and an id each', () => {
    const process = started(5);

    expect(process.stages.map((stage) => stage.position)).toEqual([1, 2, 3, 4, 5]);
    expect(process.stages.map((stage) => stage.name)).toEqual(inputs(5).map((s) => s.name));
    expect(new Set(process.stages.map((stage) => stage.id)).size).toBe(5);
  });

  it('I1: a process with a single stage, and one with 30, are valid', () => {
    for (const count of [1, MAX_STAGES_PER_PROCESS]) {
      const process = started(count);

      expect(process.stages).toHaveLength(count);
      expect(invariantViolations(process)).toEqual([]);
    }
  });

  it.each([0, MAX_STAGES_PER_PROCESS + 1])(
    'I1, E-20: %i stages are refused with a 400',
    (count) => {
      const result = startProcess({
        id: '00000000-0000-4000-8000-0000000001a1',
        client: CLIENT,
        title: 'Processo',
        stages: inputs(count),
        at: AT,
        newStageId: () => stageId(1),
      });

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error).toBeInstanceOf(ValidationError);
    },
  );

  it('keeps the description of a stage, or null', () => {
    const result = startProcess({
      id: '00000000-0000-4000-8000-0000000001a1',
      client: CLIENT,
      title: 'Processo',
      stages: [{ name: 'A', description: 'Detalhe' }, { name: 'B' }],
      at: AT,
      newStageId: (() => {
        let n = 0;
        return () => stageId(++n);
      })(),
    });

    expect(result.ok && result.value.stages.map((stage) => stage.description)).toEqual([
      'Detalhe',
      null,
    ]);
  });
});

describe('invariantViolations', () => {
  it('a process that was just started, approved at every step and cancelled is healthy', () => {
    let process = started(4);
    expect(invariantViolations(process)).toEqual([]);
    while (process.status === 'active') {
      process = approved(process);
      expect(invariantViolations(process)).toEqual([]);
    }
    expect(process.status).toBe('completed');

    const cancelled = applyProcessPatch(approved(started(4)), { cancel: true }, LATER);
    expect(cancelled.ok && invariantViolations(cancelled.value)).toEqual([]);
  });

  describe('I1: from 1 to 30 stages, position contiguous from 1', () => {
    it('refuses a process with no stage', () => {
      expect(invariantsOf({ ...started(1), stages: [] })).toContain('I1');
    });

    it('refuses a process with 31 stages', () => {
      const full = started(MAX_STAGES_PER_PROCESS);
      const extra: Stage = {
        id: stageId(MAX_STAGES_PER_PROCESS + 1),
        position: MAX_STAGES_PER_PROCESS + 1,
        name: 'Fase extra',
        description: null,
        status: 'pending',
        startedAt: null,
        completedAt: null,
        approval: null,
      };

      expect(invariantsOf({ ...full, stages: [...full.stages, extra] })).toEqual(['I1']);
    });

    it('refuses a gap in the positions', () => {
      const broken = withStages(started(3), (stages) =>
        stages.map((stage) => (stage.position === 3 ? { ...stage, position: 4 } : stage)),
      );

      expect(invariantsOf(broken)).toEqual(['I1']);
    });

    it('refuses positions that do not start at 1 or repeat', () => {
      const shifted = withStages(started(2), (stages) =>
        stages.map((stage) => ({ ...stage, position: stage.position + 1 })),
      );
      const repeated = withStages(started(2), (stages) =>
        stages.map((stage) => ({ ...stage, position: 1 })),
      );

      expect(invariantsOf(shifted)).toContain('I1');
      expect(invariantsOf(repeated)).toContain('I1');
    });
  });

  describe('I2: an active process has exactly one stage in progress, after the completed ones', () => {
    it('refuses an active process with no stage in progress', () => {
      const broken = withStages(started(3), (stages) =>
        stages.map((stage) => ({ ...stage, status: 'pending' as const, startedAt: null })),
      );

      expect(invariantsOf(broken)).toEqual(['I2']);
    });

    it('refuses two stages in progress', () => {
      const broken = withStages(started(3), (stages) =>
        stages.map((stage) =>
          stage.position === 2
            ? { ...stage, status: 'in_progress' as const, startedAt: AT }
            : stage,
        ),
      );

      expect(invariantsOf(broken)).toEqual(['I2']);
    });

    it('refuses a pending stage before the one in progress and a completed one after it', () => {
      const pendingFirst = withStages(started(3), (stages) => [
        stageAt({ ...started(3), stages }, 2),
        stageAt({ ...started(3), stages }, 1),
        stageAt({ ...started(3), stages }, 3),
      ]);
      const done = approved(started(3));
      const completedAfter = withStages(done, (stages) => [
        ...stages.slice(1, 2),
        ...stages.slice(0, 1),
        ...stages.slice(2),
      ]);

      expect(invariantsOf(pendingFirst)).toContain('I2');
      expect(invariantsOf(completedAfter)).toContain('I2');
    });

    it('refuses an active process that already has a completion or cancellation date', () => {
      expect(invariantsOf({ ...started(2), completedAt: AT })).toEqual(['I2']);
      expect(invariantsOf({ ...started(2), cancelledAt: AT })).toEqual(['I2']);
    });
  });

  describe('I3: a completed process has every stage completed and completedAt', () => {
    const finished = () => {
      let process = started(2);
      while (process.status === 'active') process = approved(process);
      return process;
    };

    it('accepts the process the last approval produced', () => {
      expect(invariantViolations(finished())).toEqual([]);
    });

    it('refuses a completed process with a stage that is not completed', () => {
      const broken = withStages(finished(), (stages) =>
        stages.map((stage) =>
          stage.position === 2
            ? { ...stage, status: 'in_progress' as const, completedAt: null, approval: null }
            : stage,
        ),
      );

      expect(invariantsOf(broken)).toContain('I3');
    });

    it('refuses a completed process with no completedAt, or with a cancelledAt', () => {
      expect(invariantsOf({ ...finished(), completedAt: null })).toEqual(['I3']);
      expect(invariantsOf({ ...finished(), cancelledAt: AT })).toEqual(['I3']);
    });
  });

  describe('I4: a cancelled process has cancelledAt and its stages frozen as they were', () => {
    const cancelled = () => {
      const result = applyProcessPatch(approved(started(3)), { cancel: true }, LATER);
      if (!result.ok) throw new Error('the fixture cancellation must pass');
      return result.value;
    };

    it('accepts the cancellation of a process in the middle: its stage in progress stays', () => {
      const process = cancelled();

      expect(invariantViolations(process)).toEqual([]);
      expect(statusesOf(process)).toEqual(['completed', 'in_progress', 'pending']);
    });

    it('refuses a cancelled process with no cancelledAt, or with a completedAt', () => {
      expect(invariantsOf({ ...cancelled(), cancelledAt: null })).toEqual(['I4']);
      expect(invariantsOf({ ...cancelled(), completedAt: AT })).toEqual(['I4']);
    });

    it('refuses stages that were reordered after the process stopped', () => {
      const broken = withStages(cancelled(), (stages) =>
        stages.map((stage) =>
          stage.position === 3
            ? { ...stage, status: 'completed' as const, startedAt: AT, completedAt: AT }
            : stage,
        ),
      );

      expect(invariantsOf(broken)).toContain('I4');
    });
  });

  describe('I5: a stage has an approval exactly when it is completed', () => {
    it('refuses a completed stage with no approval', () => {
      const broken = withStages(approved(started(3)), (stages) =>
        stages.map((stage) => (stage.position === 1 ? { ...stage, approval: null } : stage)),
      );

      expect(invariantsOf(broken)).toEqual(['I5']);
    });

    it('refuses an approval on a stage that is not completed', () => {
      const approvedProcess = approved(started(3));
      const approval = stageAt(approvedProcess, 1).approval;
      const broken = withStages(approvedProcess, (stages) =>
        stages.map((stage) => (stage.position === 2 ? { ...stage, approval } : stage)),
      );

      expect(invariantsOf(broken)).toEqual(['I5']);
    });
  });
});

describe('approveCurrentStage', () => {
  it('AC-16: completes the current stage with the CEO and the instant, and starts the next', () => {
    const process = started(3);
    const [first] = process.stages;

    const result = approveCurrentStage(process, {
      expectedStageId: first?.id ?? '',
      approver: CEO,
      at: LATER,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const next = result.value;
    expect(statusesOf(next)).toEqual(['completed', 'in_progress', 'pending']);
    expect(stageAt(next, 1)).toMatchObject({
      completedAt: LATER,
      approval: { approvedBy: { id: CEO.userId, displayName: CEO.displayName }, approvedAt: LATER },
    });
    expect(stageAt(next, 2)).toMatchObject({ startedAt: LATER, completedAt: null, approval: null });
    expect(next).toMatchObject({
      status: 'active',
      version: 2,
      updatedAt: LATER,
      completedAt: null,
    });
    expect(invariantViolations(next)).toEqual([]);
  });

  it('does not change the process it was given', () => {
    const process = started(3);
    const snapshot = JSON.stringify(process);

    approved(process);

    expect(JSON.stringify(process)).toBe(snapshot);
  });

  it('AC-18, I3: approving the last stage completes the process', () => {
    const lastOfTwo = approved(started(2));

    const result = approveCurrentStage(lastOfTwo, {
      expectedStageId: currentStageOf(lastOfTwo)?.id ?? '',
      approver: CEO,
      at: LATER,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).toMatchObject({ status: 'completed', completedAt: LATER, version: 3 });
    expect(statusesOf(result.value)).toEqual(['completed', 'completed']);
    expect(currentStageOf(result.value)).toBeNull();
    expect(invariantViolations(result.value)).toEqual([]);
  });

  it('E-04: with a single stage, the first approval completes the process', () => {
    const process = started(1);

    const done = approved(process);

    expect(done.status).toBe('completed');
    expect(done.completedAt).toEqual(LATER);
    expect(statusesOf(done)).toEqual(['completed']);
  });

  it('AC-18, E-03, I6: approving a completed process is ProcessNotActiveError, even with a stale id', () => {
    let process = started(1);
    const staleId = process.stages[0]?.id ?? '';
    process = approved(process);

    const result = approveCurrentStage(process, {
      expectedStageId: staleId,
      approver: CEO,
      at: LATER,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ProcessNotActiveError);
  });

  it('AC-19, E-03, I4, I6: approving a cancelled process is ProcessNotActiveError and changes nothing', () => {
    const process = started(3);
    const cancelled = applyProcessPatch(process, { cancel: true }, LATER);
    if (!cancelled.ok) throw new Error('the fixture cancellation must pass');

    const result = approveCurrentStage(cancelled.value, {
      expectedStageId: currentStageOf(cancelled.value)?.id ?? '',
      approver: CEO,
      at: LATER,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ProcessNotActiveError);
  });

  it('E-01, E-02, I6: a stage that is not the current one is StaleStageError with the id that is', () => {
    const process = approved(started(3));
    const current = currentStageOf(process);

    const result = approveCurrentStage(process, {
      expectedStageId: stageId(1),
      approver: CEO,
      at: LATER,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(StaleStageError);
    expect(result.error.extensions).toEqual({ currentStageId: current?.id });
  });

  it('E-02: repeating the same approval is stale, never a second advance', () => {
    const process = started(3);
    const firstId = stageId(1);
    const once = approveCurrentStage(process, {
      expectedStageId: firstId,
      approver: CEO,
      at: LATER,
    });
    if (!once.ok) throw new Error('the first approval must pass');

    const again = approveCurrentStage(once.value, {
      expectedStageId: firstId,
      approver: CEO,
      at: LATER,
    });

    expect(again.ok).toBe(false);
    if (!again.ok) expect(again.error).toBeInstanceOf(StaleStageError);
    expect(statusesOf(once.value)).toEqual(['completed', 'in_progress', 'pending']);
  });

  it('I6: an active process with no stage in progress is stale, with no current stage to name', () => {
    const broken = withStages(started(2), (stages) =>
      stages.map((stage) => ({ ...stage, status: 'pending' as const, startedAt: null })),
    );

    const result = approveCurrentStage(broken, {
      expectedStageId: stageId(1),
      approver: CEO,
      at: LATER,
    });

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(StaleStageError);
    expect(result.error.extensions).toEqual({ currentStageId: null });
  });

  it.each([
    ['a client user', { role: 'client', aal: 'aal1' }],
    ['a client user with an aal2 claim', { role: 'client', aal: 'aal2' }],
    ['a CEO whose session is aal1', { role: 'ceo', aal: 'aal1' }],
  ] as const)('I6: %s is ForbiddenError, before anything about the process', (_label, who) => {
    const process = started(2);

    const result = approveCurrentStage(process, {
      expectedStageId: stageId(1),
      approver: { ...CEO, ...who },
      at: LATER,
    });

    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.error).toBeInstanceOf(ForbiddenError);
  });

  it('walks a 30-stage process to the end, one approval at a time, keeping I1 to I5', () => {
    let process = started(MAX_STAGES_PER_PROCESS);
    let approvals = 0;

    while (process.status === 'active') {
      process = approved(process);
      approvals += 1;
      expect(invariantViolations(process)).toEqual([]);
    }

    expect(approvals).toBe(MAX_STAGES_PER_PROCESS);
    expect(process.version).toBe(1 + MAX_STAGES_PER_PROCESS);
    expect(completedStageCount(process)).toBe(MAX_STAGES_PER_PROCESS);
  });
});

describe('applyProcessPatch', () => {
  it('AC-19, I4: cancels an active process, leaving its stages as they are', () => {
    const process = approved(started(3));

    const result = applyProcessPatch(process, { cancel: true }, LATER);

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value).toMatchObject({ status: 'cancelled', cancelledAt: LATER, version: 3 });
    expect(result.value.stages).toEqual(process.stages);
    expect(result.value.completedAt).toBeNull();
  });

  it('AC-19: renames an active process and moves the version and the update instant', () => {
    const process = started(2);

    const result = applyProcessPatch(process, { title: 'Novo título' }, LATER);

    expect(result.ok && result.value).toMatchObject({
      title: 'Novo título',
      status: 'active',
      version: 2,
      updatedAt: LATER,
      cancelledAt: null,
    });
  });

  it('renaming and cancelling in one patch moves the version once', () => {
    const result = applyProcessPatch(started(2), { title: 'Fim', cancel: true }, LATER);

    expect(result.ok && result.value).toMatchObject({
      title: 'Fim',
      status: 'cancelled',
      version: 2,
    });
  });

  it('a rename to the same title changes nothing: no new version, same process', () => {
    const process = started(2, 'Igual');

    const result = applyProcessPatch(process, { title: 'Igual' }, LATER);

    expect(result.ok && result.value).toBe(process);
  });

  it.each([
    ['a completed process', () => approved(started(1))],
    [
      'a cancelled process',
      () => {
        const result = applyProcessPatch(started(2), { cancel: true }, LATER);
        if (!result.ok) throw new Error('the fixture cancellation must pass');
        return result.value;
      },
    ],
  ])('I3, I4: %s refuses every patch, even a rename to the same title', (_label, build) => {
    const process = build();

    for (const patch of [{ title: process.title }, { title: 'Outro' }, { cancel: true } as const]) {
      const result = applyProcessPatch(process, patch, LATER);

      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.error).toBeInstanceOf(ProcessNotActiveError);
    }
  });

  it('an empty patch is a 400 that points at the body', () => {
    const result = applyProcessPatch(started(2), {}, LATER);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(ValidationError);
  });
});

describe('requireProcessChange', () => {
  it('accepts a patch that renames, one that cancels and one that does both', () => {
    expect(requireProcessChange({ title: 'Novo' }).ok).toBe(true);
    expect(requireProcessChange({ cancel: true }).ok).toBe(true);
    expect(requireProcessChange({ title: 'Novo', cancel: true }).ok).toBe(true);
  });

  it('refuses an empty patch with a 400 that points at the body', () => {
    const result = requireProcessChange({});

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.issues).toEqual([
      { path: 'body', message: 'Must name at least one field to change' },
    ]);
  });
});

describe('what the panel reads of a process', () => {
  it('AC-15: the current stage is the one in progress; a completed process has none', () => {
    const process = approved(started(3));

    expect(currentStageOf(process)).toEqual({
      id: stageId(2),
      position: 2,
      name: 'Fase 2',
    });
    expect(currentStageOf(approved(started(1)))).toBeNull();
  });

  it('a cancelled process still shows the stage where it stopped', () => {
    const result = applyProcessPatch(approved(started(3)), { cancel: true }, LATER);

    expect(result.ok && currentStageOf(result.value)?.position).toBe(2);
  });

  it('summarize carries the progress and no stage list', () => {
    const process = approved(started(4));

    const summary = summarize(process);

    expect(summary).toMatchObject({
      id: process.id,
      clientId: CLIENT.id,
      title: 'Processo A',
      status: 'active',
      totalStages: 4,
      completedStages: 1,
      version: 2,
      currentStage: { position: 2 },
      completedAt: null,
      cancelledAt: null,
    });
    expect(summary).not.toHaveProperty('stages');
  });
});
