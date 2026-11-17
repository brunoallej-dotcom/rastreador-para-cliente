import { z } from 'zod';

/**
 * `ApproveStageRequest` (contract): the one thing the CEO sends is the stage they saw as current,
 * `expectedStageId`, a UUID (optimistic concurrency, I6). `.strict()`: any other field is a 400 (mass
 * assignment): the approver is the session, the process is the path, the instant is the database's.
 */
export const approveStageBodySchema = z.object({ expectedStageId: z.uuid() }).strict();

export type ApproveStageBody = z.output<typeof approveStageBodySchema>;
