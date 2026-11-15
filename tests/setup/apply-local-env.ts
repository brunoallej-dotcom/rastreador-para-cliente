// setupFiles of the `int` and `api` projects: runs inside every worker, before the test file.
// Overrides process.env on purpose, so a shell pointing at a remote project can never leak in.
import { inject } from 'vitest';

for (const [name, value] of Object.entries(inject('localEnv'))) {
  process.env[name] = value;
}
