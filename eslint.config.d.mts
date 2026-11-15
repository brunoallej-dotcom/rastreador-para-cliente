import type { Linter } from 'eslint';

export function createConfig(options?: { typeAware?: boolean }): Linter.Config[];

declare const config: Linter.Config[];
export default config;
