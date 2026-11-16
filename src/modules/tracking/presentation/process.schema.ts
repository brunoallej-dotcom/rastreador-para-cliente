import { z } from 'zod';
import { pageQueryShape, visibleText } from '@/shared/http';
import { PROCESS_STATUSES, PROCESS_TITLE_MAX_LENGTH, type ProcessPatch } from '../domain/process';
import {
  MAX_STAGES_PER_PROCESS,
  MIN_STAGES_PER_PROCESS,
  STAGE_DESCRIPTION_MAX_LENGTH,
  STAGE_NAME_MAX_LENGTH,
  type StageInput,
} from '../domain/stage';

/** The text of a process title: NFC, trimmed, 1 to 160 visible characters (E-30), as the contract. */
const processTitle = () => visibleText({ min: 1, max: PROCESS_TITLE_MAX_LENGTH });

/** `ProcessId` path parameter: a UUID. A malformed id is a 400, never a 404 (E-06). */
export const processIdParamsSchema = z.object({ processId: z.uuid() }).strict();

/**
 * Query of `GET /admin/clients/{clientId}/processes`: `limit` and `cursor` (the shared page query)
 * and an optional `status`. Anything but the three statuses is a 400.
 */
export const listClientProcessesQuerySchema = z
  .object({ ...pageQueryShape, status: z.enum(PROCESS_STATUSES).optional() })
  .strict();

/**
 * `StageInput` (contract): a name of 1 to 120 visible characters and an optional description of up to
 * 2000. The description may be empty or blank: that is no description (see `toStageInputs`).
 */
const stageInputSchema = z
  .object({
    name: visibleText({ min: 1, max: STAGE_NAME_MAX_LENGTH }),
    description: visibleText({ min: 0, max: STAGE_DESCRIPTION_MAX_LENGTH }).optional(),
  })
  .strict();

/**
 * `CreateProcessRequest` (contract): a title and, optionally, 1 to 30 stages (E-20). `.strict()`: any
 * other field, a `clientId` or a `status` included, is a 400 (mass assignment).
 */
export const createProcessBodySchema = z
  .object({
    title: processTitle(),
    stages: z
      .array(stageInputSchema)
      .min(MIN_STAGES_PER_PROCESS)
      .max(MAX_STAGES_PER_PROCESS)
      .optional(),
  })
  .strict();

/**
 * `UpdateProcessRequest` (contract): `title` and/or `status`, whose only value is `cancelled`, and at
 * least one of them (`minProperties: 1`). `.strict()`: any other field is a 400.
 */
export const updateProcessBodySchema = z
  .object({ title: processTitle().optional(), status: z.literal('cancelled').optional() })
  .strict()
  .refine((body) => body.title !== undefined || body.status !== undefined, {
    error: 'Must name at least one field to change',
  });

export type CreateProcessBody = z.output<typeof createProcessBodySchema>;
export type UpdateProcessBody = z.output<typeof updateProcessBodySchema>;

/** A blank description (the edge trims it to nothing) is no description. */
export function toStageInputs(stages: NonNullable<CreateProcessBody['stages']>): StageInput[] {
  return stages.map((stage) => ({
    name: stage.name,
    description:
      stage.description === undefined || stage.description === '' ? null : stage.description,
  }));
}

/** The body of a PATCH as the domain's patch: only the fields it carries. */
export function toProcessPatch(body: UpdateProcessBody): ProcessPatch {
  return {
    ...(body.title === undefined ? {} : { title: body.title }),
    ...(body.status === undefined ? {} : { cancel: true as const }),
  };
}
