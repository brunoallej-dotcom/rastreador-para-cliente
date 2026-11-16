import {
  progressPercent,
  type MyCurrentStage,
  type MyProcessDetail,
  type MyProcessPage,
  type MyProcessSummary,
  type MyStage,
} from '../domain/client-process-queries';
import type { ProcessStatus } from '../domain/process';
import type { StageStatus } from '../domain/stage';
import { encodeMyProcessCursor } from './my-process.cursor';

/** `MyCurrentStage` of the contract. */
export type MyCurrentStageDto = {
  readonly position: number;
  readonly name: string;
};

/** `MyStage` of the contract: where the stage is, and never who approved it. */
export type MyStageDto = {
  readonly position: number;
  readonly name: string;
  readonly description: string | null;
  readonly status: StageStatus;
  readonly startedAt: string | null;
  readonly completedAt: string | null;
};

/** `MyProcessSummary` of the contract. Explicit fields, nothing spread from a row. */
export type MyProcessSummaryDto = {
  readonly id: string;
  readonly title: string;
  readonly status: ProcessStatus;
  readonly currentStage: MyCurrentStageDto | null;
  readonly totalStages: number;
  readonly completedStages: number;
  readonly progressPercent: number;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly completedAt: string | null;
};

/** `MyProcessDetail` of the contract: the summary fields and every stage. */
export type MyProcessDetailDto = MyProcessSummaryDto & {
  readonly stages: readonly MyStageDto[];
};

/** `MyProcessList` of the contract. */
export type MyProcessListDto = {
  readonly items: readonly MyProcessSummaryDto[];
  readonly nextCursor: string | null;
};

const iso = (date: Date | null): string | null => (date === null ? null : date.toISOString());

const toCurrentStageDto = (stage: MyCurrentStage | null): MyCurrentStageDto | null =>
  stage === null ? null : { position: stage.position, name: stage.name };

function toStageDto(stage: MyStage): MyStageDto {
  return {
    position: stage.position,
    name: stage.name,
    description: stage.description,
    status: stage.status,
    startedAt: iso(stage.startedAt),
    completedAt: iso(stage.completedAt),
  };
}

export function toMyProcessSummaryDto(summary: MyProcessSummary): MyProcessSummaryDto {
  return {
    id: summary.id,
    title: summary.title,
    status: summary.status,
    currentStage: toCurrentStageDto(summary.currentStage),
    totalStages: summary.totalStages,
    completedStages: summary.completedStages,
    progressPercent: progressPercent(summary),
    createdAt: summary.createdAt.toISOString(),
    updatedAt: summary.updatedAt.toISOString(),
    completedAt: iso(summary.completedAt),
  };
}

export function toMyProcessDetailDto(process: MyProcessDetail): MyProcessDetailDto {
  return {
    ...toMyProcessSummaryDto(process),
    stages: process.stages.map(toStageDto),
  };
}

export function toMyProcessListDto(page: MyProcessPage): MyProcessListDto {
  return {
    items: page.items.map(toMyProcessSummaryDto),
    nextCursor: page.next === null ? null : encodeMyProcessCursor(page.next),
  };
}
