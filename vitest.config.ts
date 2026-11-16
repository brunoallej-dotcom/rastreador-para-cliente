import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const fromRoot = (path: string) => fileURLToPath(new URL(path, import.meta.url));

// Slower projects (int/api) share ONE local Supabase: files run one at a time.
const dbProject = {
  globalSetup: ['tests/setup/local-env.ts'],
  setupFiles: ['tests/setup/apply-local-env.ts'],
  fileParallelism: false,
  testTimeout: 30_000,
  hookTimeout: 60_000,
};

export default defineConfig({
  resolve: {
    alias: [
      { find: /^@\//, replacement: fromRoot('./src/') },
      // The real package throws outside the react-server condition.
      { find: /^server-only$/, replacement: fromRoot('./tests/stubs/server-only.ts') },
    ],
  },
  test: {
    // Wave 0 has no int/api tests yet and `vitest run --project <p>` exits 1 on an empty project.
    // Only honoured at the root, not per project.
    passWithNoTests: true,
    coverage: {
      provider: 'v8',
      include: ['src/modules/*/domain/**', 'src/modules/*/application/**'],
      // The in-memory fakes and the fixtures that only tests import are not code under test: counting
      // them would let an easy 100% in a fake pay for an untested use case.
      exclude: ['**/*.test.ts', '**/fake-*.ts', '**/*-fixtures.ts'],
      reporter: ['text-summary', 'lcov'],
      // RNF-06: at least 80% in the domain and application layers of tracking (Wave 8). The glob
      // matches a threshold per pattern: a drop below it fails `pnpm test:coverage`.
      thresholds: {
        'src/modules/tracking/{domain,application}/**': {
          statements: 80,
          branches: 80,
          functions: 80,
          lines: 80,
        },
      },
    },
    projects: [
      {
        extends: true,
        test: {
          name: 'unit',
          include: ['src/**/*.test.ts', 'tests/**/*.test.ts'],
          exclude: ['**/*.int.test.ts', '**/*.api.test.ts', '**/node_modules/**'],
        },
      },
      {
        extends: true,
        test: {
          ...dbProject,
          name: 'int',
          include: ['src/**/*.int.test.ts', 'tests/**/*.int.test.ts'],
        },
      },
      {
        extends: true,
        test: {
          ...dbProject,
          name: 'api',
          include: ['tests/api/**/*.api.test.ts'],
          // Files run one at a time (`fileParallelism: false` above), so each can start from an empty
          // global login budget: see the header of the setup file.
          setupFiles: [...dbProject.setupFiles, 'tests/setup/reset-login-budget.ts'],
        },
      },
    ],
  },
});
