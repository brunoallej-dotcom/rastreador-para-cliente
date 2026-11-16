import { describe, expect, it } from 'vitest';
import { myProcessFixture } from '../application/my-process-fixtures';
import type { MyProcessSummary } from '../domain/client-process-queries';
import { decodeMyProcessCursor } from './my-process.cursor';
import { toMyProcessDetailDto, toMyProcessListDto, toMyProcessSummaryDto } from './my-process.dto';

const AT = '2026-01-01T00:00:00.000Z';

/** Names that only an admin view, a row or an aggregate carries: none may reach the client. */
const INTERNAL_MEMBERS = [
  'version',
  'clientId',
  'client_id',
  'client',
  'cancelledAt',
  'cancelled_at',
  'approval',
  'approvedBy',
  'approvedAt',
  'approver',
  'events',
  'actor',
  'userId',
];

/** Every member name of a JSON value, at any depth. */
function memberNames(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(memberNames);
  if (typeof value !== 'object' || value === null) return [];
  return Object.entries(value).flatMap(([name, inner]) => [name, ...memberNames(inner)]);
}

describe('toMyProcessDetailDto', () => {
  it('AC-20: maps exactly the fields of MyProcessDetail, with the progress and every stage', () => {
    const process = myProcessFixture({ statuses: ['completed', 'in_progress', 'pending'] });

    const dto = toMyProcessDetailDto(process);

    expect(Object.keys(dto).sort()).toEqual(
      [
        'id',
        'title',
        'status',
        'currentStage',
        'totalStages',
        'completedStages',
        'progressPercent',
        'createdAt',
        'updatedAt',
        'completedAt',
        'stages',
      ].sort(),
    );
    expect(dto).toMatchObject({
      id: process.id,
      status: 'active',
      totalStages: 3,
      completedStages: 1,
      progressPercent: 33,
      createdAt: AT,
      updatedAt: AT,
      completedAt: null,
      currentStage: { position: 2, name: 'Fase 2' },
    });
    expect(dto.stages.map((stage) => stage.status)).toEqual([
      'completed',
      'in_progress',
      'pending',
    ]);
  });

  it('AC-20: a stage has position, name, description, status and the two dates, and nothing else', () => {
    const dto = toMyProcessDetailDto(myProcessFixture({ statuses: ['completed', 'in_progress'] }));

    for (const stage of dto.stages) {
      expect(Object.keys(stage).sort()).toEqual(
        ['completedAt', 'description', 'name', 'position', 'startedAt', 'status'].sort(),
      );
    }
    expect(dto.stages[0]).toEqual({
      position: 1,
      name: 'Fase 1',
      description: null,
      status: 'completed',
      startedAt: AT,
      completedAt: AT,
    });
    expect(dto.stages[1]).toMatchObject({
      status: 'in_progress',
      startedAt: AT,
      completedAt: null,
    });
  });

  it('AC-20: no internal member at any depth, even when the value mapped carries one', () => {
    const polluted = {
      ...myProcessFixture({ statuses: ['completed', 'in_progress'] }),
      version: 9,
      clientId: '00000000-0000-4000-8000-00000000000a',
      cancelledAt: new Date(AT),
      approval: { approvedBy: { id: '11111111-1111-4111-8111-111111111111' } },
      events: [{ action: 'stage.approved' }],
      stages: myProcessFixture({ statuses: ['completed', 'in_progress'] }).stages.map((stage) => ({
        ...stage,
        id: '00000000-0000-4000-8000-0000000002a1',
        approval: {
          approvedBy: { id: '11111111-1111-4111-8111-111111111111', displayName: 'CEO' },
        },
      })),
    };

    const names = memberNames(toMyProcessDetailDto(polluted));

    for (const internal of INTERNAL_MEMBERS) expect(names).not.toContain(internal);
    expect(JSON.stringify(toMyProcessDetailDto(polluted))).not.toContain('11111111-1111');
  });

  it('a completed process is 100 percent with no current stage, and a cancelled one keeps where it stopped', () => {
    const completed = toMyProcessDetailDto(
      myProcessFixture({
        statuses: ['completed', 'completed'],
        status: 'completed',
        completedAt: new Date(AT),
      }),
    );
    const cancelled = toMyProcessDetailDto(
      myProcessFixture({ statuses: ['completed', 'in_progress', 'pending'], status: 'cancelled' }),
    );

    expect(completed).toMatchObject({
      status: 'completed',
      currentStage: null,
      progressPercent: 100,
      completedAt: AT,
    });
    expect(cancelled).toMatchObject({
      status: 'cancelled',
      currentStage: { position: 2 },
      progressPercent: 33,
      completedAt: null,
    });
  });
});

describe('toMyProcessSummaryDto and toMyProcessListDto', () => {
  const summary = (id: string): MyProcessSummary => {
    const { stages: _stages, ...rest } = myProcessFixture({ id });
    return rest;
  };

  it('AC-20: a list row is the summary fields only, with no stages', () => {
    const dto = toMyProcessSummaryDto(summary('00000000-0000-4000-8000-0000000001a1'));

    expect(Object.keys(dto).sort()).toEqual(
      [
        'id',
        'title',
        'status',
        'currentStage',
        'totalStages',
        'completedStages',
        'progressPercent',
        'createdAt',
        'updatedAt',
        'completedAt',
      ].sort(),
    );
    expect(memberNames(dto)).not.toContain('stages');
  });

  it('carries the next position as a cursor of this endpoint, and null on the last page', () => {
    const position = {
      createdAt: '2026-11-16T11:30:24.984084+00:00',
      id: '00000000-0000-4000-8000-0000000001a1',
    };

    const more = toMyProcessListDto({ items: [summary(position.id)], next: position });
    const last = toMyProcessListDto({ items: [], next: null });

    expect(more.nextCursor).not.toBeNull();
    expect(decodeMyProcessCursor(more.nextCursor ?? '')).toEqual({ ok: true, value: position });
    expect(last).toEqual({ items: [], nextCursor: null });
  });
});
