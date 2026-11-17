import { describe, expect, it } from 'vitest';
import { progressPercent, stageOrderViolations } from './client-process-queries';
import type { StageStatus } from './stage';

describe('progressPercent', () => {
  it.each([
    [0, 3, 0],
    [1, 3, 33],
    [2, 3, 67],
    [3, 3, 100],
    [1, 1, 100],
    [0, 1, 0],
    [29, 30, 97],
    [30, 30, 100],
    [1, 6, 17],
  ])('%i of %i stages completed is %i percent', (completedStages, totalStages, expected) => {
    expect(progressPercent({ completedStages, totalStages })).toBe(expected);
  });

  it('is 100 only when every stage is completed, for any process of 1 to 30 stages', () => {
    for (let total = 1; total <= 30; total += 1) {
      for (let done = 0; done <= total; done += 1) {
        const percent = progressPercent({ completedStages: done, totalStages: total });
        expect(Number.isInteger(percent)).toBe(true);
        expect(percent).toBeGreaterThanOrEqual(0);
        expect(percent).toBeLessThanOrEqual(100);
        expect(percent === 100).toBe(done === total);
      }
    }
  });

  it.each([
    ['no stage', 0, 0],
    ['a negative total', -1, -3],
    ['more completed than stages', 4, 3],
    ['a negative count of completed stages', -1, 3],
    ['more than 30 stages', 31, 31],
    ['a count that is not a whole number', 1.5, 3],
    ['a total that is not a whole number', 1, 2.5],
    ['NaN', Number.NaN, 3],
  ])(
    'fails closed on %s: it throws, it does not answer 0 or more than 100',
    (_label, done, total) => {
      expect(() => progressPercent({ completedStages: done, totalStages: total })).toThrow(
        RangeError,
      );
    },
  );
});

const stages = (...statuses: StageStatus[]) =>
  statuses.map((status, index) => ({ position: index + 1, status }));

describe('stageOrderViolations', () => {
  it('finds nothing in a healthy process, in any state it can be in', () => {
    expect(stageOrderViolations(stages('in_progress', 'pending', 'pending'))).toEqual([]);
    expect(
      stageOrderViolations(stages('completed', 'completed', 'in_progress', 'pending')),
    ).toEqual([]);
    expect(stageOrderViolations(stages('completed', 'completed'))).toEqual([]);
    expect(stageOrderViolations(stages('pending'))).toEqual([]);
  });

  it('I2: finds stages out of order, and more than one in progress', () => {
    expect(stageOrderViolations(stages('pending', 'in_progress'))).toMatchObject([
      { invariant: 'I2' },
    ]);
    expect(
      stageOrderViolations(stages('completed', 'pending', 'in_progress', 'completed')),
    ).toMatchObject([{ invariant: 'I2' }]);
    expect(stageOrderViolations(stages('in_progress', 'in_progress'))).toMatchObject([
      { invariant: 'I2' },
    ]);
  });

  it('I1: finds positions that are not contiguous from 1', () => {
    expect(
      stageOrderViolations([
        { position: 1, status: 'completed' },
        { position: 3, status: 'in_progress' },
      ]),
    ).toMatchObject([{ invariant: 'I1' }]);
    expect(stageOrderViolations([{ position: 2, status: 'in_progress' }])).toMatchObject([
      { invariant: 'I1' },
    ]);
  });
});
