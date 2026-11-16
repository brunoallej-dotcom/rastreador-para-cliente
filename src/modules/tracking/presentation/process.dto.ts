import {
  currentStageOf,
  completedStageCount,
  type CurrentStage,
  type Process,
  type ProcessPage,
  type ProcessStatus,
  type ProcessSummary,
} from '../domain/process';
import type { Stage, StageStatus, StageTemplate } from '../domain/stage';
import { encodeProcessCursor } from './process.cursor';

/** `AdminCurrentStage` of the contract. */
export type CurrentStageDto = {
  readonly id: string;
  readonly position: number;
  readonly name: string;
};

/** `AdminStage` of the contract: the stage and, once it is completed, who approved it and when. */
export type AdminStageDto = {
  readonly id: string;
  readonly position: number;
  readonly name: string;
  readonly description: string | null;
  readonly status: StageStatus;
  readonly startedAt: string | null;
  readonly completedAt: string | null;
  readonly approval: {
    readonly approvedBy: { readonly id: string; readonly displayName: string };
    readonly approvedAt: string;
  } | null;
};

/** `ProcessSummary` of the contract. Explicit fields, nothing spread from a row. */
export type ProcessSummaryDto = {
  readonly id: string;
  readonly clientId: string;
  readonly title: string;
  readonly status: ProcessStatus;
  readonly currentStage: CurrentStageDto | null;
  readonly totalStages: number;
  readonly completedStages: number;
  readonly version: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly completedAt: string | null;
  readonly cancelledAt: string | null;
};

/** `ProcessDetail` of the contract: the summary fields, the client and every stage. */
export type ProcessDetailDto = ProcessSummaryDto & {
  readonly client: { readonly id: string; readonly name: string };
  readonly stages: readonly AdminStageDto[];
};

/** `ProcessList` of the contract. */
export type ProcessListDto = {
  readonly items: readonly ProcessSummaryDto[];
  readonly nextCursor: string | null;
};

/** `StageTemplate` of the contract. */
export type StageTemplateDto = {
  readonly stages: readonly {
    readonly position: number;
    readonly name: string;
    readonly description: string | null;
  }[];
};

const iso = (date: Date | null): string | null => (date === null ? null : date.toISOString());

const toCurrentStageDto = (stage: CurrentStage | null): CurrentStageDto | null =>
  stage === null ? null : { id: stage.id, position: stage.position, name: stage.name };

function toAdminStageDto(stage: Stage): AdminStageDto {
  return {
    id: stage.id,
    position: stage.position,
    name: stage.name,
    description: stage.description,
    status: stage.status,
    startedAt: iso(stage.startedAt),
    completedAt: iso(stage.completedAt),
    approval:
      stage.approval === null
        ? null
        : {
            approvedBy: {
              id: stage.approval.approvedBy.id,
              displayName: stage.approval.approvedBy.displayName,
            },
            approvedAt: stage.approval.approvedAt.toISOString(),
          },
  };
}

export function toProcessSummaryDto(summary: ProcessSummary): ProcessSummaryDto {
  return {
    id: summary.id,
    clientId: summary.clientId,
    title: summary.title,
    status: summary.status,
    currentStage: toCurrentStageDto(summary.currentStage),
    totalStages: summary.totalStages,
    completedStages: summary.completedStages,
    version: summary.version,
    createdAt: summary.createdAt.toISOString(),
    updatedAt: summary.updatedAt.toISOString(),
    completedAt: iso(summary.completedAt),
    cancelledAt: iso(summary.cancelledAt),
  };
}

export function toProcessDetailDto(process: Process): ProcessDetailDto {
  return {
    id: process.id,
    clientId: process.clientId,
    client: { id: process.client.id, name: process.client.name },
    title: process.title,
    status: process.status,
    currentStage: toCurrentStageDto(currentStageOf(process)),
    totalStages: process.stages.length,
    completedStages: completedStageCount(process),
    version: process.version,
    createdAt: process.createdAt.toISOString(),
    updatedAt: process.updatedAt.toISOString(),
    completedAt: iso(process.completedAt),
    cancelledAt: iso(process.cancelledAt),
    stages: process.stages.map(toAdminStageDto),
  };
}

export function toProcessListDto(page: ProcessPage): ProcessListDto {
  return {
    items: page.items.map(toProcessSummaryDto),
    nextCursor: page.next === null ? null : encodeProcessCursor(page.next),
  };
}

export function toStageTemplateDto(template: StageTemplate): StageTemplateDto {
  return {
    stages: template.stages.map((stage) => ({
      position: stage.position,
      name: stage.name,
      description: stage.description,
    })),
  };
}
