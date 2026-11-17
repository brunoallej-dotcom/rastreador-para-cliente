// Fixtures shared by the unit tests of the client panel use cases. Imported by tests only.
import { vi } from 'vitest';
import type { MyProcessDetail, MyStage } from '../domain/client-process-queries';
import type { StageStatus } from '../domain/stage';
import type { PanelLogger } from './my-tenant';

const AT = new Date('2026-01-01T00:00:00.000Z');

/** A logger that records what the use cases log, for the tests that check the trail and the signals. */
export function panelLoggerFixture() {
  const info = vi.fn();
  const error = vi.fn();
  const logger: PanelLogger = { info, error };
  return { logger, info, error };
}

/** A stage with every field set; `completed` and `in_progress` ones have started, as the table asks. */
export function myStageFixture(overrides: Partial<MyStage> & Pick<MyStage, 'position'>): MyStage {
  const status: StageStatus = overrides.status ?? 'pending';
  return {
    name: `Fase ${overrides.position}`,
    description: null,
    status,
    startedAt: status === 'pending' ? null : AT,
    completedAt: status === 'completed' ? AT : null,
    ...overrides,
  };
}

/**
 * An active process with `statuses.length` stages in the given statuses (the default is three stages,
 * the first in progress). The counters and the current stage follow from the stages.
 */
export function myProcessFixture(
  overrides: Partial<MyProcessDetail> & { readonly statuses?: readonly StageStatus[] } = {},
): MyProcessDetail {
  const { statuses = ['in_progress', 'pending', 'pending'], ...rest } = overrides;
  const stages = statuses.map((status, index) => myStageFixture({ position: index + 1, status }));
  const current = stages.find((stage) => stage.status === 'in_progress');
  return {
    id: '00000000-0000-4000-8000-0000000001a1',
    title: 'Processo A',
    status: 'active',
    currentStage: current === undefined ? null : { position: current.position, name: current.name },
    totalStages: stages.length,
    completedStages: stages.filter((stage) => stage.status === 'completed').length,
    createdAt: AT,
    updatedAt: AT,
    completedAt: null,
    stages,
    ...rest,
  };
}
