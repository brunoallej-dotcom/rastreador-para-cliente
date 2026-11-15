import type { Linter } from 'eslint';

/** Folders under src/modules/ that have layer rules. */
export const MODULES: string[];

export function createConfig(options?: { typeAware?: boolean }): Linter.Config[];

declare const config: Linter.Config[];
export default config;
