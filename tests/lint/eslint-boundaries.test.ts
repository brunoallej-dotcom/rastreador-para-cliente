// Exercises the REAL boundary rules of eslint.config.mjs through the ESLint Node API.
// Files are virtual (lintText + filePath), so the config runs with `typeAware: false`: type-aware
// rules need files that exist in the TS project. Boundary rules do not depend on type info.
import { ESLint } from 'eslint';
import { describe, expect, it, vi } from 'vitest';
import config, { createConfig } from '../../eslint.config.mjs';

vi.setConfig({ testTimeout: 30_000 });

const GUARDED_RULES = new Set(['no-restricted-imports', 'no-restricted-syntax', 'no-console']);

const eslint = new ESLint({
  cwd: process.cwd(),
  overrideConfigFile: true,
  overrideConfig: createConfig({ typeAware: false }),
});

/** Rule ids (plus any parse error) that the guarded rules raised for `code` at `filePath`. */
async function violations(filePath: string, code: string): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath });
  if (!result) throw new Error('ESLint returned no result');
  return result.messages
    .filter((m) => m.fatal === true || (m.ruleId !== null && GUARDED_RULES.has(m.ruleId)))
    .map((m) => (m.fatal === true ? `PARSE ERROR: ${m.message}` : (m.ruleId ?? '')));
}

const ROUTE = 'src/app/api/v1/admin/clients/route.ts';
const HANDLER = '@/modules/tracking/presentation/create-client.handler';

describe('route.ts: only the presentation handler may be imported', () => {
  it('passes for @/modules/<mod>/presentation/<name>.handler', async () => {
    const code = `export { createClient as POST } from '${HANDLER}';\nexport const runtime = 'nodejs';\n`;
    expect(await violations(ROUTE, code)).toEqual([]);
  });

  it('passes for the handler of another module and for a dynamic route', async () => {
    const code = `export { login as POST } from '@/modules/identity/presentation/login.handler';\n`;
    expect(await violations('src/app/api/v1/auth/login/route.ts', code)).toEqual([]);
    expect(await violations('src/app/api/v1/clients/[clientId]/route.ts', code)).toEqual([]);
  });

  it.each([
    ['infrastructure/', `export { x as POST } from '@/modules/tracking/infrastructure/x';`],
    ['domain/', `export { x as POST } from '@/modules/tracking/domain/x';`],
    ['application/', `export { x as POST } from '@/modules/tracking/application/x';`],
    ['the module index', `export { x as POST } from '@/modules/tracking';`],
    [
      'a presentation file that is not a handler',
      `export { x as POST } from '@/modules/tracking/presentation/schemas';`,
    ],
    [
      'a nested handler path',
      `export { x as POST } from '@/modules/tracking/presentation/a/b.handler';`,
    ],
    [
      '@/shared/db',
      `import { serverClient } from '@/shared/db/server-client';\nexport const c = serverClient;`,
    ],
    ['@/shared/http', `export { withRoute } from '@/shared/http/with-route';`],
    [
      '@supabase/ssr',
      `import { createServerClient } from '@supabase/ssr';\nexport const c = createServerClient;`,
    ],
    ['@supabase/supabase-js', `export { createClient } from '@supabase/supabase-js';`],
    ['next/server', `import { NextResponse } from 'next/server';\nexport const r = NextResponse;`],
    [
      'a relative path',
      `export { x as POST } from '../../../modules/tracking/presentation/x.handler';`,
    ],
    ['export *', `export * from '@/modules/tracking/infrastructure/x';`],
  ])('fails when importing %s', async (_label, code) => {
    expect(await violations(ROUTE, code)).toContain('no-restricted-imports');
  });

  it('fails on a dynamic import()', async () => {
    const code = `export const POST = async () => (await import('@/shared/db/server-client')).serverClient;`;
    expect(await violations(ROUTE, code)).toContain('no-restricted-syntax');
  });
});

describe('domain/: only its own domain and @/shared/kernel', () => {
  const FILE = 'src/modules/tracking/domain/process.ts';

  it.each([
    ['a sibling file', `import { Stage } from './stage';\nexport const s = Stage;`],
    ['a parent folder inside domain', `import { Id } from '../ids';\nexport const s = Id;`],
    ['@/shared/kernel', `import { ok } from '@/shared/kernel';\nexport const r = ok;`],
    [
      '@/shared/kernel/result',
      `import type { Result } from '@/shared/kernel/result';\nexport type R = Result<1, 2>;`,
    ],
    [
      'its own domain through the alias',
      `import { Stage } from '@/modules/tracking/domain/stage';\nexport const s = Stage;`,
    ],
  ])('passes when importing %s', async (_label, code) => {
    expect(await violations(FILE, code)).toEqual([]);
  });

  it.each([
    [
      '@supabase/supabase-js',
      `import { createClient } from '@supabase/supabase-js';\nexport const c = createClient;`,
    ],
    [
      '@supabase/ssr',
      `import { createServerClient } from '@supabase/ssr';\nexport const c = createServerClient;`,
    ],
    ['next/server', `import { NextResponse } from 'next/server';\nexport const r = NextResponse;`],
    ['pino', `import pino from 'pino';\nexport const l = pino;`],
    ['server-only', `import 'server-only';`],
    ['zod', `import { z } from 'zod';\nexport const s = z;`],
    ['@/shared/db', `import { db } from '@/shared/db/server-client';\nexport const d = db;`],
    [
      '@/shared/http',
      `import { problem } from '@/shared/http/problem';\nexport const p = problem;`,
    ],
    [
      '@/shared/observability',
      `import { logger } from '@/shared/observability/logger';\nexport const l = logger;`,
    ],
    ['@/shared/config', `import { getEnv } from '@/shared/config/env';\nexport const e = getEnv;`],
    [
      'application/ of its module',
      `import { run } from '@/modules/tracking/application/run';\nexport const r = run;`,
    ],
    [
      'infrastructure/ by relative path',
      `import { repo } from '../infrastructure/repo';\nexport const r = repo;`,
    ],
    [
      'shared/ by relative path',
      `import { db } from '../../../shared/db/server-client';\nexport const d = db;`,
    ],
  ])('fails when importing %s', async (_label, code) => {
    expect(await violations(FILE, code)).toContain('no-restricted-imports');
  });
});

describe('application/ and infrastructure/', () => {
  const APPLICATION = 'src/modules/tracking/application/approve-stage.ts';
  const INFRASTRUCTURE = 'src/modules/tracking/infrastructure/supabase-process-repository.ts';

  it.each([
    [
      'domain ports',
      `import type { Port } from '@/modules/tracking/domain/ports';\nexport type P = Port;`,
    ],
    ['@/shared/kernel', `import { ok } from '@/shared/kernel';\nexport const r = ok;`],
    [
      'the logger',
      `import { logger } from '@/shared/observability/logger';\nexport const l = logger;`,
    ],
  ])('application passes when importing %s', async (_label, code) => {
    expect(await violations(APPLICATION, code)).toEqual([]);
  });

  it.each([
    [
      'infrastructure/',
      `import { repo } from '@/modules/tracking/infrastructure/repo';\nexport const r = repo;`,
    ],
    [
      'infrastructure/ by relative path',
      `import { repo } from '../infrastructure/repo';\nexport const r = repo;`,
    ],
    [
      'presentation/',
      `import { schema } from '@/modules/tracking/presentation/schemas';\nexport const s = schema;`,
    ],
    [
      '@supabase/supabase-js',
      `import { createClient } from '@supabase/supabase-js';\nexport const c = createClient;`,
    ],
    ['@/shared/db', `import { db } from '@/shared/db/server-client';\nexport const d = db;`],
    ['next/server', `import { NextResponse } from 'next/server';\nexport const r = NextResponse;`],
  ])('application fails when importing %s', async (_label, code) => {
    expect(await violations(APPLICATION, code)).toContain('no-restricted-imports');
  });

  it.each([
    [
      '@supabase/supabase-js',
      `import { createClient } from '@supabase/supabase-js';\nexport const c = createClient;`,
    ],
    ['@/shared/db', `import { db } from '@/shared/db/server-client';\nexport const d = db;`],
    [
      'domain ports',
      `import type { Port } from '@/modules/tracking/domain/ports';\nexport type P = Port;`,
    ],
  ])('infrastructure passes when importing %s', async (_label, code) => {
    expect(await violations(INFRASTRUCTURE, code)).toEqual([]);
  });

  it.each([
    [
      'presentation/',
      `import { schema } from '@/modules/tracking/presentation/schemas';\nexport const s = schema;`,
    ],
    [
      'presentation/ by relative path',
      `import { schema } from '../presentation/schemas';\nexport const s = schema;`,
    ],
  ])('infrastructure fails when importing %s', async (_label, code) => {
    expect(await violations(INFRASTRUCTURE, code)).toContain('no-restricted-imports');
  });
});

describe('cross-module imports', () => {
  const IDENTITY_FILE = 'src/modules/identity/application/login.ts';
  const TRACKING_FILE = 'src/modules/tracking/application/create-client.ts';

  it('tracking may NEVER import identity', async () => {
    for (const source of [
      '@/modules/identity',
      '@/modules/identity/index',
      '@/modules/identity/domain/role',
      '../../../identity/index',
      '../../../modules/identity/index',
    ]) {
      const code = `import { x } from '${source}';\nexport const y = x;`;
      expect(await violations(TRACKING_FILE, code), source).toContain('no-restricted-imports');
    }
  });

  it('identity may import tracking through its index', async () => {
    const code = `import { getClientStatus } from '@/modules/tracking';\nexport const s = getClientStatus;`;
    expect(await violations(IDENTITY_FILE, code)).toEqual([]);
  });

  it('identity may not import deep tracking paths', async () => {
    for (const source of [
      '@/modules/tracking/domain/client',
      '@/modules/tracking/application/get-client-status',
      '@/modules/tracking/index',
      '../../../tracking/index',
    ]) {
      const code = `import { x } from '${source}';\nexport const y = x;`;
      expect(await violations(IDENTITY_FILE, code), source).toContain('no-restricted-imports');
    }
  });

  it('a module may import its own deep paths through the alias', async () => {
    const code = `import { Client } from '@/modules/tracking/domain/client';\nexport const c = Client;`;
    expect(await violations(TRACKING_FILE, code)).toEqual([]);
  });

  it('the module index file follows the same rules', async () => {
    const code = `export { x } from '@/modules/identity';`;
    expect(await violations('src/modules/tracking/index.ts', code)).toContain(
      'no-restricted-imports',
    );
    expect(
      await violations('src/modules/identity/index.ts', `export { x } from '@/modules/tracking';`),
    ).toEqual([]);
  });
});

describe('src/shared/ never imports modules', () => {
  it.each([
    ['the alias', `import { x } from '@/modules/tracking';\nexport const y = x;`],
    ['a deep alias', `import { x } from '@/modules/tracking/domain/x';\nexport const y = x;`],
    ['a relative path', `import { x } from '../../modules/tracking';\nexport const y = x;`],
  ])('fails through %s', async (_label, code) => {
    expect(await violations('src/shared/http/with-route.ts', code)).toContain(
      'no-restricted-imports',
    );
  });

  it('allows importing other shared folders', async () => {
    const code = `import { ok } from '@/shared/kernel';\nexport const r = ok;`;
    expect(await violations('src/shared/http/with-route.ts', code)).toEqual([]);
  });
});

describe('next/headers', () => {
  it.each([
    'src/shared/http/cookies.ts',
    'src/modules/identity/presentation/login.handler.ts',
    'src/modules/tracking/domain/x.ts',
    'src/app/api/v1/health/route.ts',
  ])('is forbidden in %s', async (file) => {
    const code = `import { cookies } from 'next/headers';\nexport const c = cookies;`;
    expect(await violations(file, code)).toContain('no-restricted-imports');
  });
});

describe('PostgREST filters and getSession (no-restricted-syntax)', () => {
  const FILE = 'src/modules/tracking/infrastructure/supabase-client-queries.ts';

  it.each([
    ['template literal in .or()', 'query.or(`name.eq.${name}`);'],
    ['template literal in .filter()', "query.filter('name', 'eq', `${name}`);"],
    ['template literal in .textSearch()', "query.textSearch('name', `${term}`);"],
    ['concatenation in .or()', "query.or('name.eq.' + name);"],
    ['concatenation in .filter()', "query.filter('name', 'eq', 'x' + name);"],
    ['auth.getSession() on a client', 'await supabase.auth.getSession();'],
    ['auth.getSession() on a nested client', 'await this.deps.client.auth.getSession();'],
    ['auth.getSession() on a bare auth', 'await auth.getSession();'],
  ])('fails on %s', async (_label, statement) => {
    const code = `declare const query: any, supabase: any, auth: any, name: string, term: string;\n${statement}\n`;
    expect(await violations(FILE, code)).toContain('no-restricted-syntax');
  });

  it.each([
    ['a static template literal in .or()', 'query.or(`name.eq.fixed`);'],
    ['a plain string in .or()', "query.or('name.eq.fixed');"],
    ['.eq() with a variable', "query.eq('name', name);"],
    ['Array#filter with a callback', 'const kept = [1, 2].filter((n) => n > 1);'],
    ['auth.getUser()', 'await supabase.auth.getUser();'],
    ['auth.getClaims()', 'await supabase.auth.getClaims();'],
  ])('passes on %s', async (_label, statement) => {
    const code = `declare const query: any, supabase: any, name: string;\n${statement}\n`;
    expect(await violations(FILE, code)).toEqual([]);
  });

  it('applies to scripts/ as well', async () => {
    const code = 'declare const q: any, v: string;\nq.or(`a.eq.${v}`);\n';
    expect(await violations('scripts/create-ceo.ts', code)).toContain('no-restricted-syntax');
  });
});

describe('no-console', () => {
  it('fails in src/', async () => {
    expect(await violations('src/shared/http/x.ts', "console.log('hi');")).toContain('no-console');
    expect(await violations('src/modules/tracking/domain/x.ts', "console.error('hi');")).toContain(
      'no-console',
    );
  });

  it('is allowed in tests/ and scripts/', async () => {
    expect(await violations('tests/helpers/x.ts', "console.log('hi');")).toEqual([]);
    expect(await violations('scripts/create-ceo.ts', "console.log('hi');")).toEqual([]);
  });
});

describe('the real eslint.config.mjs', () => {
  it('applies the same boundary rules the test just proved', async () => {
    const real = new ESLint({ cwd: process.cwd() });
    for (const file of [
      'src/app/api/v1/admin/clients/route.ts',
      'src/modules/tracking/domain/x.ts',
      'src/modules/tracking/application/x.ts',
      'src/modules/identity/infrastructure/x.ts',
      'src/shared/http/x.ts',
    ]) {
      const actual = (await real.calculateConfigForFile(file)) as {
        rules: Record<string, unknown>;
      };
      const expected = (await eslint.calculateConfigForFile(file)) as {
        rules: Record<string, unknown>;
      };
      for (const rule of ['no-restricted-imports', 'no-restricted-syntax', 'no-console']) {
        expect(actual.rules[rule], `${rule} @ ${file}`).toEqual(expected.rules[rule]);
      }
    }
  });

  it('exports a default config built by createConfig', () => {
    expect(Array.isArray(config)).toBe(true);
    expect(config.length).toBeGreaterThan(0);
  });
});
