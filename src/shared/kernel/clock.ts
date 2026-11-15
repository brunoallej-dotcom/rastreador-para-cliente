export interface Clock {
  now(): Date;
}

export const systemClock: Clock = {
  now: () => new Date(),
};

/** Deterministic clock for tests. Each call returns a fresh copy of the same instant. */
export function fixedClock(date: Date): Clock {
  return { now: () => new Date(date.getTime()) };
}
