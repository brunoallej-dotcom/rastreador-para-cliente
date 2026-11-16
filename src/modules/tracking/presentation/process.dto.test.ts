import { describe, expect, it } from 'vitest';
import { CLIENT_A, processFixture, stageIdOf } from '../application/process-fixtures';
import { summarize } from '../domain/process';
import { decodeProcessCursor } from './process.cursor';
import {
  toProcessDetailDto,
  toProcessListDto,
  toProcessSummaryDto,
  toStageTemplateDto,
} from './process.dto';

const AT = '2026-01-01T00:00:00.000Z';

describe('toProcessDetailDto', () => {
  it('AC-15: maps the fields of ProcessDetail, with the client, the progress and every stage', () => {
    const process = processFixture({ statuses: ['completed', 'in_progress', 'pending'] });

    const dto = toProcessDetailDto(process);

    expect(Object.keys(dto).sort()).toEqual(
      [
        'id',
        'clientId',
        'client',
        'title',
        'status',
        'currentStage',
        'totalStages',
        'completedStages',
        'version',
        'createdAt',
        'updatedAt',
        'completedAt',
        'cancelledAt',
        'stages',
      ].sort(),
    );
    expect(dto).toMatchObject({
      id: process.id,
      clientId: CLIENT_A.id,
      client: CLIENT_A,
      status: 'active',
      totalStages: 3,
      completedStages: 1,
      version: 1,
      createdAt: AT,
      updatedAt: AT,
      completedAt: null,
      cancelledAt: null,
      currentStage: { position: 2, name: 'Fase 2' },
    });
    expect(dto.stages.map((stage) => stage.status)).toEqual([
      'completed',
      'in_progress',
      'pending',
    ]);
  });

  it('AC-16: a completed stage carries who approved it and when; the others carry null', () => {
    const dto = toProcessDetailDto(
      processFixture({ statuses: ['completed', 'in_progress', 'pending'] }),
    );

    expect(dto.stages[0]).toEqual({
      id: stageIdOf(1),
      position: 1,
      name: 'Fase 1',
      description: null,
      status: 'completed',
      startedAt: AT,
      completedAt: AT,
      approval: {
        approvedBy: { id: '11111111-1111-4111-8111-111111111111', displayName: 'CEO' },
        approvedAt: AT,
      },
    });
    expect(dto.stages[1]).toMatchObject({ completedAt: null, approval: null, startedAt: AT });
    expect(dto.stages[2]).toMatchObject({ startedAt: null, completedAt: null, approval: null });
  });

  it('each stage has exactly the fields of AdminStage', () => {
    const [stage] = toProcessDetailDto(processFixture()).stages;

    expect(Object.keys(stage ?? {}).sort()).toEqual(
      [
        'id',
        'position',
        'name',
        'description',
        'status',
        'startedAt',
        'completedAt',
        'approval',
      ].sort(),
    );
  });

  it('a completed process has no current stage; a cancelled one still shows where it stopped', () => {
    const completed = processFixture({
      status: 'completed',
      completedAt: new Date(AT),
      statuses: ['completed', 'completed'],
    });
    const cancelled = processFixture({
      status: 'cancelled',
      cancelledAt: new Date(AT),
      statuses: ['completed', 'in_progress'],
    });

    expect(toProcessDetailDto(completed)).toMatchObject({
      currentStage: null,
      completedAt: AT,
      completedStages: 2,
    });
    expect(toProcessDetailDto(cancelled)).toMatchObject({
      currentStage: { position: 2 },
      cancelledAt: AT,
    });
  });
});

describe('toProcessSummaryDto', () => {
  it('maps the fields of ProcessSummary and nothing else', () => {
    const process = processFixture({ statuses: ['completed', 'in_progress', 'pending'] });

    const dto = toProcessSummaryDto(summarize(process));

    expect(dto).toEqual({
      id: process.id,
      clientId: CLIENT_A.id,
      title: 'Processo A',
      status: 'active',
      currentStage: { id: process.stages[1]?.id, position: 2, name: 'Fase 2' },
      totalStages: 3,
      completedStages: 1,
      version: 1,
      createdAt: AT,
      updatedAt: AT,
      completedAt: null,
      cancelledAt: null,
    });
    expect(dto).not.toHaveProperty('stages');
    expect(dto).not.toHaveProperty('client');
  });
});

describe('toProcessListDto', () => {
  it('has no cursor on the last page', () => {
    const dto = toProcessListDto({ items: [summarize(processFixture())], next: null });

    expect(dto.nextCursor).toBeNull();
    expect(dto.items).toHaveLength(1);
  });

  it('turns the next position into an opaque cursor that decodes back to it', () => {
    const next = { createdAt: '2026-11-16T11:30:24.984084+00:00', id: processFixture().id };

    const dto = toProcessListDto({ items: [], next });

    expect(dto.nextCursor).toEqual(expect.any(String));
    expect(decodeProcessCursor(dto.nextCursor ?? '')).toEqual({ ok: true, value: next });
  });
});

describe('toStageTemplateDto', () => {
  it('maps the stages with position, name and description, in order', () => {
    expect(
      toStageTemplateDto({
        stages: [
          { position: 1, name: 'Contrato', description: null },
          { position: 2, name: 'Briefing', description: 'Levantamento' },
        ],
      }),
    ).toEqual({
      stages: [
        { position: 1, name: 'Contrato', description: null },
        { position: 2, name: 'Briefing', description: 'Levantamento' },
      ],
    });
  });
});
