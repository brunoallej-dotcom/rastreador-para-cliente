import { afterEach, describe, expect, it, vi } from 'vitest';
import { register } from './instrumentation';

describe('register()', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it('fails at boot on the Node.js runtime when the env is invalid', async () => {
    vi.stubEnv('NEXT_RUNTIME', 'nodejs');
    for (const name of [
      'APP_ORIGIN',
      'SUPABASE_URL',
      'SUPABASE_PUBLISHABLE_KEY',
      'SUPABASE_SECRET_KEY',
      'RATE_LIMIT_KEY_SECRET',
    ]) {
      vi.stubEnv(name, undefined);
    }
    await expect(register()).rejects.toThrow(/SUPABASE_URL/);
  });

  it('does nothing on other runtimes', async () => {
    vi.stubEnv('NEXT_RUNTIME', 'edge');
    await expect(register()).resolves.toBeUndefined();
  });
});
