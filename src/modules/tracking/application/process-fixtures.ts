// Fixtures shared by the unit tests of the process use cases. Imported by tests only.
import type { Process } from '../domain/process';
import type { Stage, StageStatus } from '../domain/stage';

export const CLIENT_A = { id: '00000000-0000-4000-8000-00000000000a', name: 'Cliente A' } as const;

const AT = new Date('2026-01-01T00:00:00.000Z');

/** A stage with every field set; the caller overrides what the test is about. */
export function stageFixture(overrides: Partial<Stage> & Pick<Stage, 'id' | 'position'>): Stage {
  const status: StageStatus = overrides.status ?? 'pending';
  return {
    name: `Fase ${overrides.position}`,
    description: null,
    status,
    startedAt: status === 'pending' ? null : AT,
    completedAt: status === 'completed' ? AT : null,
    approval:
      status === 'completed'
        ? {
            approvedBy: { id: '11111111-1111-4111-8111-111111111111', displayName: 'CEO' },
            approvedAt: AT,
          }
        : null,
    ...overrides,
  };
}

/** The id of the n-th stage of a fixture process. */
export const stageIdOf = (position: number) =>
  `00000000-0000-4000-8000-0000000002${String(position).padStart(2, '0')}`;

/**
 * An active process of `CLIENT_A` with `statuses.length` stages in the given statuses (the default is
 * three stages, the first in progress). `completed` stages get an approval, as I5 asks.
 */
export function processFixture(
  overrides: Partial<Process> & { readonly statuses?: readonly StageStatus[] } = {},
): Process {
  const { statuses = ['in_progress', 'pending', 'pending'], ...rest } = overrides;
  return {
    id: '00000000-0000-4000-8000-0000000001a1',
    clientId: CLIENT_A.id,
    client: CLIENT_A,
    title: 'Processo A',
    status: 'active',
    version: 1,
    createdAt: AT,
    updatedAt: AT,
    completedAt: null,
    cancelledAt: null,
    stages: statuses.map((status, index) =>
      stageFixture({ id: stageIdOf(index + 1), position: index + 1, status }),
    ),
    ...rest,
  };
}
