import { z } from 'zod';

/**
 * A `timestamptz` as PostgREST sends it, e.g. `2026-11-16T11:30:24.984084+00:00`: any sub-second
 * precision, always with an offset. One definition for every row the tracking module reads, so two
 * readers of the same column cannot disagree on its shape.
 */
export const timestampSchema = z.iso.datetime({ offset: true });
