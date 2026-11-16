import { describe, expect, it } from 'vitest';
import { ValidationError } from '@/shared/kernel';
import {
  MAX_STAGES_PER_PROCESS,
  STAGE_DESCRIPTION_MAX_LENGTH,
  STAGE_NAME_MAX_LENGTH,
  validateStageInputs,
  type StageInput,
} from './stage';

const stages = (count: number): StageInput[] =>
  Array.from({ length: count }, (_value, index) => ({ name: `Fase ${index + 1}` }));

describe('validateStageInputs', () => {
  it('I1: accepts from 1 to 30 stages and keeps their order', () => {
    for (const count of [1, 2, MAX_STAGES_PER_PROCESS]) {
      const result = validateStageInputs(stages(count));

      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.value.map((stage) => stage.name)).toEqual(
          stages(count).map((stage) => stage.name),
        );
      }
    }
  });

  it('AC-15: a missing description becomes null, a given one is kept', () => {
    const result = validateStageInputs([
      { name: 'A' },
      { name: 'B', description: null },
      { name: 'C', description: 'Detalhe' },
    ]);

    expect(result.ok && result.value).toEqual([
      { name: 'A', description: null },
      { name: 'B', description: null },
      { name: 'C', description: 'Detalhe' },
    ]);
  });

  it.each([
    ['an empty list', 0],
    ['31 stages', MAX_STAGES_PER_PROCESS + 1],
  ])('E-20, I1: %s is a 400 that points at body.stages', (_label, count) => {
    const result = validateStageInputs(stages(count));

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toBeInstanceOf(ValidationError);
    expect(result.error.issues.map((issue) => issue.path)).toEqual(['body.stages']);
  });

  it('E-20: a name of only spaces, or over 120 characters, points at the stage that has it', () => {
    const result = validateStageInputs([
      { name: 'Boa' },
      { name: '   ' },
      { name: 'x'.repeat(STAGE_NAME_MAX_LENGTH + 1) },
      { name: 'x'.repeat(STAGE_NAME_MAX_LENGTH) },
    ]);

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error.issues.map((issue) => issue.path)).toEqual([
      'body.stages[1].name',
      'body.stages[2].name',
    ]);
  });

  it('E-20: a description over 2000 characters points at its stage; 2000 is fine', () => {
    const tooLong = validateStageInputs([
      { name: 'A', description: 'd'.repeat(STAGE_DESCRIPTION_MAX_LENGTH + 1) },
    ]);
    const justRight = validateStageInputs([
      { name: 'A', description: 'd'.repeat(STAGE_DESCRIPTION_MAX_LENGTH) },
    ]);

    expect(tooLong.ok).toBe(false);
    if (!tooLong.ok) {
      expect(tooLong.error.issues.map((issue) => issue.path)).toEqual([
        'body.stages[0].description',
      ]);
    }
    expect(justRight.ok).toBe(true);
  });

  it('counts characters, not UTF-16 units: 120 emoji-free code points of 4 bytes are fine', () => {
    const astral = String.fromCodePoint(0x1d54f);

    const result = validateStageInputs([{ name: astral.repeat(STAGE_NAME_MAX_LENGTH) }]);

    expect(result.ok).toBe(true);
  });

  it('collects the problems of the list and of the stages together', () => {
    const result = validateStageInputs([...stages(MAX_STAGES_PER_PROCESS), { name: ' ' }]);

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error.issues.map((issue) => issue.path)).toEqual([
        'body.stages',
        `body.stages[${MAX_STAGES_PER_PROCESS}].name`,
      ]);
    }
  });
});
