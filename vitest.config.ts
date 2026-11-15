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
      exclude: ['**/*.test.ts'],
      reporter: ['text-summary', 'lcov'],
      // Thresholds arrive in Wave 8.
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
        },
      },
    ],
  },
});
