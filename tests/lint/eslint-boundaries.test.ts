// Exercises the REAL boundary rules of eslint.config.mjs through the ESLint Node API.
// Files are virtual (lintText + filePath), so the config runs with `typeAware: false`: type-aware
// rules need files that exist in the TS project. Boundary rules do not depend on type info.
import { existsSync, readdirSync } from 'node:fs';
import { ESLint } from 'eslint';
import { describe, expect, it, vi } from 'vitest';
import config, { MODULES, createConfig } from '../../eslint.config.mjs';

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

  it('fails on require() and on import() types', async () => {
    expect(await violations(ROUTE, `export const c = require('@supabase/supabase-js');`)).toContain(
      'no-restricted-syntax',
    );
    expect(
      await violations(ROUTE, `export type C = import('@supabase/supabase-js').SupabaseClient;`),
    ).toContain('no-restricted-syntax');
  });

  // The route rules must be linted (and must fire) whatever the extension of the route file.
  it.each(['ts', 'tsx', 'js', 'jsx', 'mjs', 'mts', 'cts'])('covers route.%s', async (ext) => {
    const file = `src/app/api/v1/admin/clients/route.${ext}`;
    const bad = `export { createClient } from '@supabase/supabase-js';`;
    expect(await violations(file, bad)).toContain('no-restricted-imports');
    const dynamic = `export const POST = async () => import('@/shared/db/server-client');`;
    expect(await violations(file, dynamic)).toContain('no-restricted-syntax');
    expect(await violations(file, `export { createClient as POST } from '${HANDLER}';`)).toEqual(
      [],
    );
  });

  it('covers route.cjs', async () => {
    const file = 'src/app/api/v1/admin/clients/route.cjs';
    expect(await violations(file, `module.exports = require('@supabase/supabase-js');`)).toContain(
      'no-restricted-syntax',
    );
  });

  it.each([
    [
      'a ".." inside the alias',
      `export { x as POST } from '@/modules/tracking/presentation/../infrastructure/x.handler';`,
    ],
    [
      'a ".." that leaves modules/',
      `export { x as POST } from '@/modules/../presentation/x.handler';`,
    ],
  ])('fails on %s', async (_label, code) => {
    expect(await violations(ROUTE, code)).toContain('no-restricted-imports');
  });
});

describe('domain/: only its own domain and @/shared/kernel', () => {
  const FILE = 'src/modules/tracking/domain/process.ts';

  it.each([
    ['a sibling file', `import { Stage } from './stage';\nexport const s = Stage;`],
    ['a sibling in a sub-folder', `import { Id } from './ids/id';\nexport const s = Id;`],
    [
      'its own domain through a relative path',
      `import { Id } from '../domain/ids';\nexport const s = Id;`,
    ],
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

describe('the admin client (secret key, bypasses RLS) has exactly two doors', () => {
  const ADMIN = '@/shared/db/admin-client';
  const importAdmin = (source = ADMIN) =>
    `import { getAdminFacade } from '${source}';\nexport const admin = getAdminFacade;`;

  it.each([
    ['the rate limiter', 'src/shared/http/rate-limit/postgres-rate-limiter.ts', importAdmin()],
    ['a test beside the rate limiter', 'src/shared/http/rate-limit/x.int.test.ts', importAdmin()],
    [
      'a nested file of the rate limiter, by a relative path',
      'src/shared/http/rate-limit/deep/x.ts',
      importAdmin('../../../db/admin-client'),
    ],
    [
      'identity infrastructure',
      'src/modules/identity/infrastructure/supabase-account-gateway.ts',
      importAdmin(),
    ],
    [
      'a test beside identity infrastructure',
      'src/modules/identity/infrastructure/supabase-account-gateway.test.ts',
      importAdmin(),
    ],
    [
      'a nested file of identity infrastructure',
      'src/modules/identity/infrastructure/accounts/gateway.ts',
      importAdmin(),
    ],
  ])('allows %s', async (_label, file, code) => {
    expect(await violations(file, code)).toEqual([]);
  });

  it.each([
    'src/shared/http/with-route.ts',
    'src/shared/http/pipeline-deps.ts',
    'src/shared/http/supabase-principal-resolver.ts',
    'src/shared/db/server-client.ts',
    'src/shared/kernel/index.ts',
    'src/shared/observability/logger.ts',
    'src/instrumentation.ts',
    'src/modules/identity/domain/session.ts',
    'src/modules/identity/application/login.ts',
    'src/modules/identity/presentation/login.handler.ts',
    'src/modules/identity/index.ts',
    'src/modules/tracking/infrastructure/supabase-client-directory.ts',
    'src/modules/tracking/application/approve-current-stage.ts',
    'src/modules/tracking/presentation/approve-current-stage.handler.ts',
    'src/modules/platform/presentation/health.handler.ts',
    'src/app/api/v1/auth/login/route.ts',
  ])('refuses %s', async (file) => {
    expect(await violations(file, importAdmin()), file).toContain('no-restricted-imports');
  });

  it.each([
    ['the alias with an extension', importAdmin('@/shared/db/admin-client.ts')],
    ['a relative path inside shared/db', importAdmin('./admin-client')],
    ['a relative path from a sibling folder', importAdmin('../db/admin-client')],
    ['a re-export', `export { getAdminFacade } from '${ADMIN}';`],
    ['export *', `export * from '${ADMIN}';`],
    [
      'a type-only import',
      `import type { AdminFacade } from '${ADMIN}';\nexport type T = AdminFacade;`,
    ],
    ['a ".." segment that hides the path', importAdmin('@/shared/kernel/../db/admin-client')],
  ])('refuses %s, wherever it is not a door', async (_label, code) => {
    expect(await violations('src/shared/db/current-principal.ts', code)).toContain(
      'no-restricted-imports',
    );
  });

  it.each([
    // a folder or file whose name only STARTS like a door
    'src/shared/http/rate-limit-extra/x.ts',
    'src/shared/http/rate-limit.ts',
    'src/shared/http/rate-limiter/x.ts',
    'src/modules/identity/infrastructure-extra/x.ts',
    'src/modules/identity/infrastructure.ts',
    // the doors of ANOTHER module or of another shared folder
    'src/modules/tracking/infrastructure/x.ts',
    'src/shared/db/x.ts',
  ])('is not fooled by the look-alike path %s', async (file) => {
    expect(await violations(file, importAdmin()), file).toContain('no-restricted-imports');
  });

  it('refuses a dynamic import() of it, even at the doors', async () => {
    const code = `export const load = () => import('${ADMIN}');`;
    for (const file of [
      'src/shared/http/with-route.ts',
      'src/shared/http/rate-limit/postgres-rate-limiter.ts',
      'src/modules/identity/infrastructure/supabase-account-gateway.ts',
    ]) {
      expect(await violations(file, code), file).toContain('no-restricted-syntax');
    }
  });

  it('keeps every other import rule alive at the doors (modules stay out of shared/)', async () => {
    const code = `import { x } from '@/modules/tracking';\nexport const y = x;`;
    expect(await violations('src/shared/http/rate-limit/postgres-rate-limiter.ts', code)).toContain(
      'no-restricted-imports',
    );
    // and identity infrastructure still may not reach into presentation/ or deep tracking paths
    expect(
      await violations(
        'src/modules/identity/infrastructure/x.ts',
        `import { h } from '@/modules/identity/presentation/login.handler';\nexport const y = h;`,
      ),
    ).toContain('no-restricted-imports');
    expect(
      await violations(
        'src/modules/identity/infrastructure/x.ts',
        `import { d } from '@/modules/tracking/domain/client';\nexport const y = d;`,
      ),
    ).toContain('no-restricted-imports');
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
    ['getSession destructured from .auth', 'const { getSession } = supabase.auth;'],
    ['getSession destructured from a bare auth', 'const { getSession } = auth;'],
    ['getSession destructured with a rename', 'const { getSession: read } = supabase.auth;'],
    ['getSession destructured with a string key', "const { 'getSession': read } = supabase.auth;"],
    ['getSession destructured from an optional .auth', 'const { getSession } = supabase?.auth;'],
    ['getSession destructured by assignment', 'let g: any; ({ getSession: g } = supabase.auth);'],
    ['getSession destructured from a nested pattern', 'const { auth: { getSession } } = supabase;'],
    [
      'getSession as a parameter pattern',
      'const f = ({ auth: { getSession } }: any) => getSession;',
    ],
    ['computed auth.getSession()', "await supabase.auth['getSession']();"],
    ['computed template auth.getSession()', 'await supabase.auth[`getSession`]();'],
    ['computed auth and getSession', "await supabase['auth']['getSession']();"],
    ['optional auth?.getSession()', 'await supabase.auth?.getSession();'],
    ['a reference to auth.getSession', 'const read = supabase.auth.getSession;'],
    ['a variable as the .or() filter', 'query.or(filters);'],
    ['a call as the .or() filter', 'query.or(buildFilter(name));'],
    ['`x`.concat() as the .or() filter', 'query.or(`name.eq.`.concat(name));'],
    ['a conditional as the .or() filter', "query.or(name ? 'a.eq.1' : 'b.eq.2');"],
    ['a member as the .or() filter', 'query.or(filters.main);'],
    ['a variable plus options in .or()', "query.or(filters, { referencedTable: 't' });"],
    ['a computed .or() with a variable', "query['or'](filters);"],
    ['an optional .or() with a variable', 'query?.or(filters);'],
    ['a variable as the .filter() column', "query.filter(column, 'eq', 'x');"],
    ['a call as the .filter() column', "query.filter(columnFor(name), 'eq', 'x');"],
    ['a variable as the .textSearch() column', "query.textSearch(column, 'x');"],
    ['a call as the .textSearch() column', "query.textSearch(columnFor(name), 'x');"],
    ['next/headers through import()', "await import('next/headers');"],
  ])('fails on %s', async (_label, statement) => {
    const code = `declare const query: any, supabase: any, auth: any, name: string, term: string, filters: any, column: string, buildFilter: any, columnFor: any;\n${statement}\n`;
    expect(await violations(FILE, code)).toContain('no-restricted-syntax');
  });

  it.each([
    ['a static template literal in .or()', 'query.or(`name.eq.fixed`);'],
    ['a plain string in .or()', "query.or('name.eq.fixed');"],
    ['.eq() with a variable', "query.eq('name', name);"],
    ['Array#filter with a callback', 'const kept = [1, 2].filter((n) => n > 1);'],
    ['auth.getUser()', 'await supabase.auth.getUser();'],
    ['auth.getClaims()', 'await supabase.auth.getClaims();'],
    ['computed auth.getUser()', "await supabase.auth['getUser']();"],
    ['destructuring getUser from .auth', 'const { getUser } = supabase.auth;'],
    ['destructuring auth itself', 'const { auth } = supabase;'],
    ['a getSession of something that is not auth', 'const { getSession } = cookieStore;'],
    [
      'a string literal as the .or() filter with options',
      "query.or('a.eq.1,b.eq.2', { referencedTable: 't' });",
    ],
    ['a static template as the .or() filter', 'query.or(`a.eq.1,b.eq.2`);'],
    ['.filter() with a literal column', "query.filter('name', 'eq', name);"],
    ['.textSearch() with a literal column and a variable query', "query.textSearch('name', name);"],
    ['.textSearch() with a literal column', "query.textSearch('name', 'x');"],
    ['Array#filter with an identifier callback', 'const kept = [1, 2].filter(isOdd);'],
    [
      'Array#filter with a function callback',
      'const kept = [1, 2].filter(function (n) { return n > 1; });',
    ],
    [
      'Array#filter with a callback and a thisArg',
      'const kept = [1, 2].filter((n) => n > 1, query);',
    ],
    ['Zod .or() with a call chain', 'z.string().or(z.number().int().positive());'],
    ['dynamic import() of other modules', "await import('@/shared/config/env');"],
  ])('passes on %s', async (_label, statement) => {
    const code = `declare const query: any, supabase: any, cookieStore: any, isOdd: (n: number) => boolean, z: any, name: string;\n${statement}\n`;
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

describe('M1: ".." and "." segments cannot hide a forbidden path', () => {
  // One file per config object: the pattern must be in every layer's own list.
  const FILES = [
    'src/modules/tracking/domain/process.ts',
    'src/modules/tracking/domain/stages/stage.ts',
    'src/modules/tracking/application/approve-stage.ts',
    'src/modules/tracking/infrastructure/repo.ts',
    'src/modules/tracking/presentation/create-client.handler.ts',
    'src/modules/tracking/index.ts',
    'src/modules/tracking/lib/helper.ts',
    'src/modules/platform/presentation/health.handler.ts',
    'src/shared/http/with-route.ts',
    'src/instrumentation.ts',
    'src/app/api/v1/health/route.ts',
  ];
  const BYPASSES = [
    '@/shared/kernel/../db/admin-client',
    '@/modules/tracking/domain/../infrastructure/r',
    '@/shared/kernel/..',
    '@/..',
    '@/../shared/db/admin-client',
    '@/shared/./db/admin-client',
    '@/shared//db/admin-client',
    '@/modules/tracking/presentation/x/../../infrastructure/y',
  ];

  it.each(FILES)('rejects alias imports with ".." segments in %s', async (file) => {
    for (const source of BYPASSES) {
      const code = `import { x } from '${source}';\nexport const y = x;`;
      expect(await violations(file, code), `${file}: ${source}`).toContain('no-restricted-imports');
    }
  });

  it.each(FILES)('rejects "export ... from" with ".." segments in %s', async (file) => {
    const code = `export { x } from '@/shared/kernel/../db/admin-client';`;
    expect(await violations(file, code)).toContain('no-restricted-imports');
  });

  it('keeps accepting canonical aliases', async () => {
    for (const file of FILES.filter((f) => !f.includes('/app/'))) {
      const code = `import { ok } from '@/shared/kernel/result';\nexport const r = ok;`;
      // domain, application and the rest all may import the kernel; only the route may not.
      expect(await violations(file, code), file).toEqual([]);
    }
  });

  it('rejects ".." segments in the middle of a relative path', async () => {
    const FILE = 'src/modules/tracking/presentation/create-client.handler.ts';
    for (const source of [
      '../x/../../identity/index',
      '../../identity/../identity/index',
      './x/../../../identity/index',
      '../x/..',
      '../.',
      '.././x',
    ]) {
      const code = `import { x } from '${source}';\nexport const y = x;`;
      expect(await violations(FILE, code), source).toContain('no-restricted-imports');
    }
  });

  it('counts a leading "./" before the ".." segments', async () => {
    const code = `import { x } from './../../identity/index';\nexport const y = x;`;
    expect(await violations('src/modules/tracking/presentation/x.ts', code)).toContain(
      'no-restricted-imports',
    );
    const shared = `import { x } from './../../modules/tracking';\nexport const y = x;`;
    expect(await violations('src/shared/http/x.ts', shared)).toContain('no-restricted-imports');
  });

  it('still accepts ordinary relative imports', async () => {
    for (const source of ['./sibling', '../sibling', '../../kernel/result', './a/b/c']) {
      const code = `import { x } from '${source}';\nexport const y = x;`;
      expect(await violations('src/shared/http/with-route.ts', code), source).toEqual([]);
    }
  });
});

describe('M2: relative imports from domain/ and application/ stay in their layers', () => {
  const DOMAIN = 'src/modules/tracking/domain/process.ts';
  const DOMAIN_NESTED = 'src/modules/tracking/domain/stages/stage.ts';
  // 9 folders below domain/: deeper than the per-depth configs, which must fail closed.
  const DOMAIN_DEEP = 'src/modules/tracking/domain/a/b/c/d/e/f/g/h/i/deep.ts';
  const APPLICATION = 'src/modules/tracking/application/approve-stage.ts';
  const APPLICATION_NESTED = 'src/modules/tracking/application/approvals/approve.ts';
  const imports = (source: string) => `import { x } from '${source}';\nexport const y = x;`;

  it.each([
    [DOMAIN, './stage'],
    [DOMAIN, './stages/stage'],
    [DOMAIN, '../domain/ids'],
    [DOMAIN_NESTED, '../ids'],
    [DOMAIN_NESTED, './sibling'],
    [DOMAIN_NESTED, '../../domain/ids'],
    [DOMAIN_DEEP, './sibling'],
    [DOMAIN_DEEP, '../sibling'],
    [DOMAIN_DEEP, '../../sibling'],
    [APPLICATION, './sibling'],
    [APPLICATION, '../domain/ports'],
    [APPLICATION, '../application/other'],
    [APPLICATION_NESTED, './sibling'],
    [APPLICATION_NESTED, '../sibling'],
    [APPLICATION_NESTED, '../../domain/ports'],
    [APPLICATION_NESTED, '../../application/other'],
  ])('passes: %s imports %s', async (file, source) => {
    expect(await violations(file, imports(source))).toEqual([]);
  });

  it.each([
    // The module root and its index.
    [DOMAIN, '../../index'],
    [DOMAIN, '../index'],
    [DOMAIN, '../'],
    [DOMAIN, '..'],
    [DOMAIN, '../..'],
    [DOMAIN, '../../foo'],
    [DOMAIN, '../foo'],
    [DOMAIN, './../index'],
    [DOMAIN, '../../../../x'],
    [DOMAIN_NESTED, '../../index'],
    [DOMAIN_NESTED, '../..'],
    [DOMAIN_NESTED, '../../foo'],
    [DOMAIN_NESTED, '../../../x'],
    [DOMAIN_DEEP, `${'../'.repeat(10)}index`],
    [DOMAIN_DEEP, '../'.repeat(12) + 'x'],
    // Other layers of the module, by relative path.
    [DOMAIN, '../application/x'],
    [DOMAIN_NESTED, '../../infrastructure/repo'],
    [DOMAIN_NESTED, '../../presentation/handler'],
    // Application: no module root, no index, no infrastructure/presentation, no shared/.
    [APPLICATION, '..'],
    [APPLICATION, '../'],
    [APPLICATION, '../..'],
    [APPLICATION, '../index'],
    [APPLICATION, '../../index'],
    [APPLICATION, '../foo'],
    [APPLICATION, '../infrastructure/repo'],
    [APPLICATION, '../presentation/schemas'],
    [APPLICATION, '../../../shared/db/server-client'],
    [APPLICATION, '../../../../x'],
    [APPLICATION_NESTED, '../../index'],
    [APPLICATION_NESTED, '../..'],
    [APPLICATION_NESTED, '../../foo'],
    [APPLICATION_NESTED, '../../infrastructure/repo'],
    [APPLICATION_NESTED, '../../presentation/schemas'],
    [APPLICATION_NESTED, '../../../shared/db/server-client'],
    [APPLICATION_NESTED, '../../../x'],
  ])('fails: %s imports %s', async (file, source) => {
    expect(await violations(file, imports(source))).toContain('no-restricted-imports');
  });

  it('also covers "export ... from"', async () => {
    expect(await violations(DOMAIN, `export { x } from '../../index';`)).toContain(
      'no-restricted-imports',
    );
    expect(await violations(APPLICATION, `export * from '../index';`)).toContain(
      'no-restricted-imports',
    );
  });

  it('applies to the other modules and to .tsx files', async () => {
    expect(await violations('src/modules/identity/domain/role.ts', imports('../index'))).toContain(
      'no-restricted-imports',
    );
    expect(
      await violations('src/modules/platform/application/health.tsx', imports('../../index')),
    ).toContain('no-restricted-imports');
    expect(
      await violations('src/modules/platform/application/health.tsx', imports('../domain/ports')),
    ).toEqual([]);
  });
});

describe('test files beside domain/ and application/ code may import vitest', () => {
  const imports = (source: string) => `import { x } from '${source}';\nexport const y = x;`;
  const VITEST = `import { describe, expect, it } from 'vitest';\ndescribe('x', () => it('y', () => expect(1).toBe(1)));`;
  /** `n` climbs: `../` repeated. */
  const up = (n: number) => '../'.repeat(n);
  /** The layer root seen from a file `depth` folders below it (`./` when the file is in it). */
  const sameDir = (depth: number) => (depth === 0 ? './' : up(depth));
  /** The module a file belongs to, so alias imports target its own layers. */
  const moduleOf = (file: string) => /^src\/modules\/([^/]+)\//.exec(file)?.[1] ?? '';

  // [file, folders between the layer root and the file]
  const DOMAIN_TESTS: [string, number][] = [
    ['src/modules/tracking/domain/process.test.ts', 0],
    ['src/modules/tracking/domain/process.int.test.ts', 0],
    ['src/modules/tracking/domain/process.test.tsx', 0],
    ['src/modules/tracking/domain/process.test.mts', 0],
    ['src/modules/tracking/domain/stages/stage.test.ts', 1],
    ['src/modules/identity/domain/a/b/role.int.test.ts', 2],
    ['src/modules/platform/domain/health.test.ts', 0],
  ];
  const APPLICATION_TESTS: [string, number][] = [
    ['src/modules/tracking/application/approve-stage.test.ts', 0],
    ['src/modules/tracking/application/approve-stage.int.test.ts', 0],
    ['src/modules/tracking/application/approvals/approve.test.ts', 1],
    ['src/modules/identity/application/login.test.mts', 0],
  ];

  it.each(DOMAIN_TESTS)('domain test %s passes importing vitest', async (file) => {
    expect(await violations(file, VITEST)).toEqual([]);
  });

  it.each(DOMAIN_TESTS)(
    'domain test %s keeps its own domain and the kernel',
    async (file, depth) => {
      for (const source of [
        'vitest',
        './sibling',
        './sub/fake',
        `${sameDir(depth)}ids`,
        `${up(depth + 1)}domain/ids`,
        `@/modules/${moduleOf(file)}/domain/ids`,
        '@/shared/kernel',
        '@/shared/kernel/result',
      ]) {
        expect(await violations(file, imports(source)), `${file}: ${source}`).toEqual([]);
      }
    },
  );

  it('keeps vi.mock hoisting and vi.hoisted usable in domain and application tests', async () => {
    const code = [
      `import { vi } from 'vitest';`,
      `import { now } from './clock';`,
      `const h = vi.hoisted(() => ({ ms: 1 }));`,
      `vi.mock('./clock', () => ({ now: () => h.ms }));`,
      `vi.mock('@/shared/kernel', async () => vi.importActual('@/shared/kernel'));`,
      `export const t = now;`,
    ].join('\n');
    expect(await violations('src/modules/tracking/domain/clock.test.ts', code)).toEqual([]);
    expect(await violations('src/modules/tracking/application/clock.test.ts', code)).toEqual([]);
  });

  it.each(DOMAIN_TESTS)('domain test %s still cannot import anything else', async (file, depth) => {
    for (const source of [
      '@supabase/supabase-js',
      '@supabase/ssr',
      '@/shared/db/server-client',
      '@/shared/http/problem',
      `@/modules/${moduleOf(file)}/infrastructure/x`,
      `@/modules/${moduleOf(file)}/application/x`,
      `@/modules/${moduleOf(file)}/domain/../infrastructure/x`,
      `${up(depth + 1)}infrastructure/x`,
      `${up(depth + 1)}application/x`,
      `${up(depth + 1)}index`,
      `${up(depth + 1)}foo`,
      `${up(depth + 4)}shared/db/server-client`,
      up(depth + 1).slice(0, -1),
      up(depth + 2).slice(0, -1),
      `${up(depth + 2)}x`,
      'zod',
      'pino',
      'next/server',
      'vitest/config',
      '@vitest/ui',
      'vitest/../zod',
    ]) {
      expect(await violations(file, imports(source)), `${file}: ${source}`).toContain(
        'no-restricted-imports',
      );
    }
  });

  it.each([
    'src/modules/tracking/domain/process.ts',
    'src/modules/tracking/domain/process.tsx',
    'src/modules/tracking/domain/stages/stage.ts',
    'src/modules/tracking/domain/test-helpers.ts',
    'src/modules/tracking/domain/process.test-helpers.ts',
    'src/modules/tracking/domain/process.spec.ts',
    'src/modules/tracking/domain/tests/process.ts',
    'src/modules/tracking/domain/process.test.ts.ts',
  ])('non-test domain file %s cannot import vitest', async (file) => {
    expect(await violations(file, VITEST)).toContain('no-restricted-imports');
  });

  it.each(APPLICATION_TESTS)(
    'application test %s passes importing vitest and in-memory fakes',
    async (file, depth) => {
      expect(await violations(file, VITEST)).toEqual([]);
      for (const source of [
        './in-memory-fake',
        `${sameDir(depth)}fakes`,
        `${up(depth + 1)}domain/ports`,
        `${up(depth + 1)}application/fakes`,
        `@/modules/${moduleOf(file)}/domain/ports`,
        `@/modules/${moduleOf(file)}/application/fakes`,
        '@/shared/kernel',
      ]) {
        expect(await violations(file, imports(source)), `${file}: ${source}`).toEqual([]);
      }
    },
  );

  it.each(APPLICATION_TESTS)(
    'application test %s still cannot import infrastructure, I/O or escape',
    async (file, depth) => {
      for (const source of [
        '@supabase/supabase-js',
        '@/shared/db/server-client',
        'next/server',
        `@/modules/${moduleOf(file)}/infrastructure/x`,
        `@/modules/${moduleOf(file)}/presentation/x`,
        `@/modules/${moduleOf(file)}/application/../infrastructure/x`,
        `${up(depth + 1)}infrastructure/x`,
        `${up(depth + 1)}presentation/x`,
        `${up(depth + 1)}index`,
        `${up(depth + 1)}foo`,
        `${up(depth + 4)}shared/db/server-client`,
        up(depth + 1).slice(0, -1),
        up(depth + 2).slice(0, -1),
        `${up(depth + 2)}x`,
      ]) {
        expect(await violations(file, imports(source)), `${file}: ${source}`).toContain(
          'no-restricted-imports',
        );
      }
    },
  );

  it('keeps forbidding dynamic loading in test files', async () => {
    // import() and `typeof import()` are flagged in test files too. Not a problem for
    // vi.mock/vi.hoisted, only for `importOriginal<typeof import('./x')>()`: use a type import.
    for (const file of [
      'src/modules/tracking/domain/clock.test.ts',
      'src/modules/tracking/application/clock.test.ts',
    ]) {
      expect(await violations(file, `export const m = await import('./clock');`), file).toContain(
        'no-restricted-syntax',
      );
      expect(await violations(file, `export type M = typeof import('./clock');`), file).toContain(
        'no-restricted-syntax',
      );
      expect(
        await violations(
          file,
          `import type * as Clock from './clock';\nexport type M = typeof Clock;`,
        ),
        file,
      ).toEqual([]);
    }
  });
});

describe('M3: dynamic loading and file extensions', () => {
  const EXTENSIONS = ['ts', 'tsx', 'mts', 'cts', 'js', 'jsx', 'mjs'];

  it.each(['domain', 'application'])('forbids import() in %s/', async (layer) => {
    const file = `src/modules/tracking/${layer}/x.ts`;
    for (const code of [
      `export const load = async () => import('@supabase/supabase-js');`,
      `export const load = async () => (await import('@supabase/supabase-js')).createClient;`,
      `export const load = async (name: string) => import(name);`,
      `export const load = async () => import('./sibling');`,
    ]) {
      expect(await violations(file, code), code).toContain('no-restricted-syntax');
    }
  });

  it.each(['domain', 'application'])(
    'forbids require() and import() types in %s/',
    async (layer) => {
      const file = `src/modules/tracking/${layer}/x.ts`;
      for (const code of [
        `export const c = require('@supabase/supabase-js');`,
        `import c = require('@supabase/supabase-js');\nexport const d = c;`,
        `export type C = import('@supabase/supabase-js').SupabaseClient;`,
      ]) {
        expect(await violations(file, code), code).toContain('no-restricted-syntax');
      }
    },
  );

  it('forbids require() in a .cjs file of domain/', async () => {
    const code = `module.exports = require('@supabase/supabase-js');`;
    expect(await violations('src/modules/tracking/domain/x.cjs', code)).toContain(
      'no-restricted-syntax',
    );
  });

  it.each([
    'src/instrumentation.ts',
    'src/shared/config/load.ts',
    'src/modules/tracking/infrastructure/lazy.ts',
    'src/modules/tracking/presentation/lazy.handler.ts',
    'src/modules/tracking/index.ts',
  ])('still allows import() in %s', async (file) => {
    const code = `export const load = async () => (await import('@/shared/config/env')).getEnv();`;
    expect(await violations(file, code)).toEqual([]);
  });

  it.each(EXTENSIONS)('applies the domain/ rules to x.%s', async (ext) => {
    const file = `src/modules/tracking/domain/x.${ext}`;
    const bad = `import { createClient } from '@supabase/supabase-js';\nexport const c = createClient;`;
    expect(await violations(file, bad)).toContain('no-restricted-imports');
    const relative = `import { x } from '../../index';\nexport const y = x;`;
    expect(await violations(file, relative)).toContain('no-restricted-imports');
    const ok = `import { x } from './sibling';\nexport const y = x;`;
    expect(await violations(file, ok)).toEqual([]);
  });

  it.each(EXTENSIONS)('applies the application/ rules to x.%s', async (ext) => {
    const file = `src/modules/tracking/application/x.${ext}`;
    const bad = `import { repo } from '@/modules/tracking/infrastructure/repo';\nexport const r = repo;`;
    expect(await violations(file, bad)).toContain('no-restricted-imports');
  });

  it.each(EXTENSIONS)('applies the infrastructure/ rules to x.%s', async (ext) => {
    const file = `src/modules/tracking/infrastructure/x.${ext}`;
    const bad = `import { h } from '@/modules/tracking/presentation/h';\nexport const r = h;`;
    expect(await violations(file, bad)).toContain('no-restricted-imports');
  });

  it.each(EXTENSIONS)('applies the cross-module and src/shared rules to x.%s', async (ext) => {
    const bad = `import { x } from '@/modules/identity';\nexport const y = x;`;
    expect(await violations(`src/modules/tracking/presentation/x.${ext}`, bad)).toContain(
      'no-restricted-imports',
    );
    expect(await violations(`src/shared/http/x.${ext}`, bad)).toContain('no-restricted-imports');
  });

  it.each(EXTENSIONS)('applies the src-wide rules to x.%s', async (ext) => {
    const headers = `import { cookies } from 'next/headers';\nexport const c = cookies;`;
    expect(await violations(`src/shared/http/x.${ext}`, headers)).toContain(
      'no-restricted-imports',
    );
    expect(await violations(`src/shared/http/x.${ext}`, "console.log('hi');")).toContain(
      'no-console',
    );
  });
});

describe('MODULES (B2)', () => {
  const MODULES_DIR = 'src/modules';

  it('has a layer-rule entry for every folder under src/modules/', () => {
    const folders = existsSync(MODULES_DIR)
      ? readdirSync(MODULES_DIR, { withFileTypes: true })
          .filter((entry) => entry.isDirectory())
          .map((entry) => entry.name)
      : [];
    const missing = folders.filter((folder) => !MODULES.includes(folder));
    expect(
      missing,
      `add ${missing.join(', ')} to MODULES in eslint.config.mjs, or the module has no layer rules`,
    ).toEqual([]);
  });

  it('names the modules of the architecture, including platform (health, Wave 1)', () => {
    expect(MODULES).toEqual(expect.arrayContaining(['identity', 'tracking', 'platform']));
    expect(new Set(MODULES).size).toBe(MODULES.length);
  });

  it.each(MODULES)('enforces the layer rules inside %s', async (mod) => {
    const base = `src/modules/${mod}`;
    const supabase = `import { createClient } from '@supabase/supabase-js';\nexport const c = createClient;`;
    expect(await violations(`${base}/domain/x.ts`, supabase)).toContain('no-restricted-imports');
    expect(await violations(`${base}/application/x.ts`, supabase)).toContain(
      'no-restricted-imports',
    );
    expect(
      await violations(
        `${base}/infrastructure/x.ts`,
        `import { h } from '@/modules/${mod}/presentation/h';\nexport const r = h;`,
      ),
    ).toContain('no-restricted-imports');
    expect(
      await violations(
        `${base}/presentation/x.handler.ts`,
        `import { x } from '@/modules/${mod === 'identity' ? 'platform' : 'identity'}/domain/x';\nexport const y = x;`,
      ),
    ).toContain('no-restricted-imports');
  });

  it('applies the cross-module rules to folders that are not a layer', async () => {
    const code = `import { x } from '@/modules/identity/domain/x';\nexport const y = x;`;
    expect(await violations('src/modules/tracking/lib/helper.ts', code)).toContain(
      'no-restricted-imports',
    );
    expect(await violations('src/modules/tracking/helper.ts', code)).toContain(
      'no-restricted-imports',
    );
  });

  it('lets the platform handler be reached by a route', async () => {
    const code = `export { health as GET } from '@/modules/platform/presentation/health.handler';`;
    expect(await violations('src/app/api/v1/health/route.ts', code)).toEqual([]);
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
      'src/modules/identity/presentation/x.tsx',
      'src/modules/platform/presentation/health.handler.ts',
      'src/modules/tracking/lib/x.ts',
      'src/modules/tracking/domain/a/b/c/x.ts',
      'src/modules/tracking/domain/x.test.ts',
      'src/modules/tracking/domain/a/b/x.int.test.ts',
      'src/modules/tracking/application/a/x.mts',
      'src/modules/tracking/application/a/x.test.ts',
      'src/modules/tracking/domain/a/b/c/d/e/f/g/h/i/x.ts',
      'src/app/api/v1/admin/clients/route.js',
      'src/instrumentation.ts',
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
