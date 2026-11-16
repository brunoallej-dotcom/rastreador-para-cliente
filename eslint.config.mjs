// @ts-check
// Flat config. `createConfig` is exported so tests/lint/eslint-boundaries.test.ts exercises the
// REAL boundary rules (with `typeAware: false`, because virtual files are not in the TS project).
import js from '@eslint/js';
import nextPlugin from '@next/eslint-plugin-next';
import { defineConfig, globalIgnores } from 'eslint/config';
import globals from 'globals';
import tseslint from 'typescript-eslint';

/**
 * Every folder under src/modules/ needs an entry here, or it is born without layer rules.
 * tests/lint/eslint-boundaries.test.ts compares this list with the folders on disk.
 * `platform` has no folder yet: Wave 1 creates src/modules/platform/presentation/health.handler.ts.
 */
export const MODULES = ['identity', 'tracking', 'platform'];
/** Modules a module may not import at all (not even through the index). */
const FORBIDDEN_MODULE_DEPS = { tracking: ['identity'] };

/** Every extension a source file may have: layer and route globs must not miss `.tsx`/`.js`/`.mts`. */
const CODE_EXT = '{ts,tsx,mts,cts,js,jsx,mjs,cjs}';
const SRC_FILES = [`src/**/*.${CODE_EXT}`];
/** Test files that live beside the code they test (`x.test.ts`, `x.int.test.ts`). */
const TEST_FILES = '*.test.{ts,tsx,mts}';
/** The only package a domain test may import besides its own domain and the kernel. */
const TEST_RUNNER = 'vitest';
/** Folders inside a layer (domain/a/b/c.ts is depth 2) with their own relative-import limit. */
const MAX_LAYER_DEPTH = 6;
const NEXT_HEADERS = {
  name: 'next/headers',
  message:
    'Do not use next/headers: the pipeline reads NextRequest and writes NextResponse (spec §3.3).',
};

// ------------------------------------------------------------ no-restricted-syntax ----

const POSTGREST_CALL = "CallExpression[callee.type='MemberExpression']";
/** `.or()/.filter()/.textSearch()`, by name or by computed string (`q['or'](...)`). */
const POSTGREST_ANY =
  ':matches([callee.property.name=/^(or|filter|textSearch)$/], [callee.property.value=/^(or|filter|textSearch)$/])';
/**
 * Calls whose FIRST argument is structure, not a value: `.or(filters)`, `.textSearch(column, ...)`
 * and `.filter(column, operator, value)`. `.filter` with one argument is `Array#filter`
 * (PostgREST's takes three), so it is not guarded.
 */
const POSTGREST_STRUCTURE =
  ':matches([callee.property.name=/^(or|textSearch)$/], [callee.property.value=/^(or|textSearch)$/], ' +
  "[callee.property.name='filter'][arguments.length>=2], [callee.property.value='filter'][arguments.length>=2])";
/** First arguments that cannot carry input: literals, static templates and callbacks. */
const SAFE_FIRST_ARGUMENTS = [
  "[arguments.0.type='Literal']",
  "[arguments.0.type='TemplateLiteral'][arguments.0.expressions.length=0]",
  "[arguments.0.type='ArrowFunctionExpression']",
  "[arguments.0.type='FunctionExpression']",
  // Zod also has `.or()`: `schema.or(z.number().int())` is a call chain rooted at `z`.
  ...Array.from({ length: 8 }, (_, i) => `[arguments.0${'.callee.object'.repeat(i + 1)}.name='z']`),
];
const POSTGREST_MESSAGE =
  'Interpolated/concatenated input in a PostgREST filter allows injection (spec §3.8). ' +
  'Use .eq/.in/.ilike with a plain value or an RPC.';
const POSTGREST_FIRST_ARGUMENT_MESSAGE =
  'The first argument of .or()/.filter()/.textSearch() must be a plain string literal: a variable, ' +
  'call, concatenation or interpolated template allows PostgREST injection (spec §3.8). ' +
  'Use .eq/.in/.ilike with a plain value or an RPC.';

/** A member access to `getSession` through `.auth`, `['auth']` or a bare `auth`. */
const AUTH_OBJECT =
  ":matches([object.property.name='auth'], [object.property.value='auth'], [object.name='auth'])";
const GET_SESSION_KEY =
  ":matches([computed=false][key.name='getSession'], [key.value='getSession'])";
const AUTH_SOURCE = (/** @type {string} */ field) =>
  `:matches([${field}.property.name='auth'], [${field}.property.value='auth'], [${field}.name='auth'], ` +
  `[${field}.expression.property.name='auth'], [${field}.expression.property.value='auth'])`;
const GET_SESSION_SELECTORS = [
  // supabase.auth.getSession(), supabase.auth?.getSession, supabase['auth']['getSession']()
  `MemberExpression${AUTH_OBJECT}:matches([computed=false][property.name='getSession'], [computed=true][property.value='getSession'])`,
  // supabase.auth[`getSession`]()
  `MemberExpression${AUTH_OBJECT}[computed=true][property.type='TemplateLiteral'][property.expressions.length=0][property.quasis.0.value.cooked='getSession']`,
  // const { getSession } = supabase.auth;  ({ getSession } = supabase.auth);
  `VariableDeclarator${AUTH_SOURCE('init')} > ObjectPattern.id > Property${GET_SESSION_KEY}`,
  `AssignmentExpression${AUTH_SOURCE('right')} > ObjectPattern.left > Property${GET_SESSION_KEY}`,
  // const { auth: { getSession } } = supabase;  function f({ auth: { getSession } }) {}
  `Property:matches([key.name='auth'][computed=false], [key.value='auth']) > ObjectPattern.value > Property${GET_SESSION_KEY}`,
];

const FORBIDDEN_SYNTAX = [
  {
    selector: `${POSTGREST_CALL}${POSTGREST_ANY} > TemplateLiteral.arguments[expressions.length>0]`,
    message: POSTGREST_MESSAGE,
  },
  {
    selector: `${POSTGREST_CALL}${POSTGREST_ANY} > BinaryExpression[operator='+'].arguments`,
    message: POSTGREST_MESSAGE,
  },
  {
    selector: `${POSTGREST_CALL}${POSTGREST_STRUCTURE}:not(${SAFE_FIRST_ARGUMENTS.join(', ')})`,
    message: POSTGREST_FIRST_ARGUMENT_MESSAGE,
  },
  ...GET_SESSION_SELECTORS.map((selector) => ({
    selector,
    message:
      'auth.getSession() does not validate the JWT on the server. Use getClaims()/getUser() through the PrincipalResolver.',
  })),
  {
    selector: "ImportExpression[source.value='next/headers']",
    message:
      'Do not use next/headers: the pipeline reads NextRequest and writes NextResponse (spec §3.3).',
  },
  {
    // the static-import restriction (ADMIN_CLIENT) cannot see a dynamic import()
    selector: 'ImportExpression[source.value=/admin-client$/]',
    message:
      'Do not import the admin client dynamically: it may be imported (statically) only from the rate limiter and identity/infrastructure.',
  },
];

/**
 * no-restricted-imports only sees static `import`/`export ... from`. In layers that must stay
 * pure, every other way to load a module (or a module's types) would escape the layer rules.
 */
const DYNAMIC_LOADING = [
  {
    selector: 'ImportExpression',
    message: 'Dynamic import() escapes the layer rules here; use a static import.',
  },
  {
    selector: "CallExpression[callee.name='require']",
    message: 'require() escapes the layer rules here; use a static import.',
  },
  {
    selector: "TSImportEqualsDeclaration[moduleReference.type='TSExternalModuleReference']",
    message: 'import x = require() escapes the layer rules here; use a static import.',
  },
  {
    selector: 'TSImportType',
    message: "import('…') types escape the layer rules here; use a static `import type`.",
  },
];

/** `no-restricted-syntax` value for files of layers that must stay pure (domain, application). */
const PURE_LAYER_SYNTAX = ['error', ...FORBIDDEN_SYNTAX, ...DYNAMIC_LOADING];

// ------------------------------------------------------------ no-restricted-imports ----

/** @param {string} message @param {string} regex */
const pattern = (regex, message) => ({ regex, message });

/**
 * Alias and relative specifiers must be canonical, otherwise `..`/`.` segments bypass every
 * pattern below (`@/shared/kernel/../db/admin-client` starts like an allowed import):
 * - a `..` segment after a normal segment (`@/a/../b`, `./a/../../b`, `@/..`);
 * - a `.` segment after the first one (`@/a/./b`, `../.`);
 * - an empty segment (`@/a//b`).
 * Only leading `./` and `../` runs remain, which the layer patterns count.
 */
const NON_CANONICAL_SPECIFIER = pattern(
  String.raw`^(?=@/|\.{1,2}(?:/|$)).*(?:/\.(?:/|$)|//|(?:^|/)(?!\.{1,2}(?:/|$))[^/]+/(?:.*/)?\.\.(?:/|$))`,
  'Import specifiers may not contain ".."/"." segments after the first or empty segments: they bypass the module boundary rules. Write the canonical path.',
);

/**
 * The admin client holds the Supabase secret key and BYPASSES RLS (SEC-15). Only the rate limiter
 * (`src/shared/http/rate-limit/`) and identity's infrastructure (`src/modules/identity/infrastructure/`,
 * the Auth Admin API) may import it; everywhere else in src/ any specifier that ends in
 * `admin-client` (alias, relative, with or without an extension) is refused. The two allowed places
 * use `restrictImportsAllowingAdminClient`.
 */
const ADMIN_CLIENT = pattern(
  String.raw`(?:^|/)admin-client(?:\.[cm]?[jt]sx?)?$`,
  'The admin client (secret key, bypasses RLS) may be imported only from src/shared/http/rate-limit/ and src/modules/identity/infrastructure/. Business reads and writes use the request-scoped client.',
);

/**
 * no-restricted-imports options. `next/headers`, non-canonical specifiers and the admin client are
 * forbidden everywhere in src/. Later config objects REPLACE earlier ones for the same rule, so
 * each layer lists its full set: going through this helper is what puts the shared patterns in
 * every list.
 * @param {readonly { regex: string, message: string }[]} always
 * @param {...{ regex: string, message: string }} patterns
 */
const restrictImportsWith = (always, ...patterns) => [
  'error',
  { paths: [NEXT_HEADERS], patterns: [NON_CANONICAL_SPECIFIER, ...always, ...patterns] },
];

/** @param {...{ regex: string, message: string }} patterns */
const restrictImports = (...patterns) => restrictImportsWith([ADMIN_CLIENT], ...patterns);

/** Only for the two places allowed to import the admin client (see ADMIN_CLIENT). */
const restrictImportsAllowingAdminClient = (
  /** @type {{ regex: string, message: string }[]} */ ...patterns
) => restrictImportsWith([], ...patterns);

const alt = (/** @type {string[]} */ names) => names.join('|');

/** `@/modules/<mod>/<layer>` imports. */
const aliasLayers = (/** @type {string} */ mod, /** @type {string[]} */ layers, message) =>
  pattern(String.raw`^@/modules/${mod}/(?:${alt(layers)})(?:/|$)`, message);

/** Relative imports (`../infrastructure/x`, `./a/presentation/y`) that land in one of the folders. */
const relativeLayers = (/** @type {string[]} */ layers, message) =>
  pattern(String.raw`^\.{1,2}/(?:.*/)?(?:${alt(layers)})(?:/|$)`, message);

/**
 * Relative imports that stay inside the allowed layers of the module. A file `depth` folders below
 * its layer root (domain/x.ts is 0, domain/a/x.ts is 1) can climb `depth` times and stay in the layer;
 * `depth + 1` climbs land on the module root, where only `allowedLayers` may come next; more
 * climbs leave the module. The specifier is canonical (NON_CANONICAL_SPECIFIER), so counting
 * the leading `..` segments is enough: after `depth + 1` of them nothing but an allowed layer
 * may follow (another `..`, the module index or any other folder is rejected).
 */
const relativeStayWithin = (
  /** @type {number} */ depth,
  /** @type {string[]} */ allowedLayers,
  /** @type {string} */ message,
) =>
  pattern(
    String.raw`^(?:\./)?(?:\.\.(?:/|$)){${depth + 1}}(?!(?:${alt(allowedLayers)})(?:/|$))`,
    message,
  );

/** Cross-module rules for files of module `mod`. */
const crossModulePatterns = (/** @type {string} */ mod) => {
  const others = MODULES.filter((m) => m !== mod);
  const forbidden =
    FORBIDDEN_MODULE_DEPS[/** @type {keyof typeof FORBIDDEN_MODULE_DEPS} */ (mod)] ?? [];
  return [
    pattern(
      String.raw`^@/modules/(?!${mod}(?:/|$))[^/]+/.+`,
      'A module may import another one only through its index (e.g. "@/modules/tracking"), never deep paths.',
    ),
    ...(forbidden.length > 0
      ? [
          pattern(
            String.raw`^@/modules/(?:${alt(forbidden)})(?:/|$)`,
            `Module "${mod}" must never import ${forbidden.join(', ')} (one-way dependency, no cycles).`,
          ),
        ]
      : []),
    ...(others.length > 0
      ? [
          pattern(
            String.raw`^(?:\./)?(?:\.\./)+(?:modules/)?(?:${alt(others)})(?:/|$)`,
            'Do not reach into another module with relative paths; use its index through the "@/modules/<name>" alias.',
          ),
        ]
      : []),
  ];
};

/** Rules for src/modules/<mod>/**. */
const moduleLayerConfigs = (/** @type {string} */ mod) => {
  const base = `src/modules/${mod}`;
  const cross = crossModulePatterns(mod);
  /**
   * One config object per folder depth inside the layer; later objects win, so a file at depth N
   * gets the limits for N (deeper than MAX_LAYER_DEPTH it keeps the strictest-for-its-depth ones,
   * which fails closed).
   */
  const byDepth = (
    /** @type {string} */ layer,
    /** @type {(depth: number) => unknown} */ imports,
    /** @type {unknown} */ syntax,
    /** @type {string} */ fileGlob = `*.${CODE_EXT}`,
    /** @type {string} */ nameSuffix = '',
  ) =>
    Array.from({ length: MAX_LAYER_DEPTH + 1 }, (_, depth) => ({
      name: `boundaries/${mod}/${layer}${nameSuffix}/depth-${depth}`,
      files: [`${base}/${layer}/${'*/'.repeat(depth)}**/${fileGlob}`],
      rules: {
        'no-restricted-imports': imports(depth),
        ...(depth === 0 && syntax !== undefined ? { 'no-restricted-syntax': syntax } : {}),
      },
    }));
  /** domain/ imports; test files may also import the test runner and nothing else new. */
  const domainImports = (/** @type {number} */ depth, /** @type {boolean} */ isTestFile) =>
    restrictImports(
      // Allow-only: relative paths inside domain, own domain via alias, shared/kernel.
      pattern(
        String.raw`^(?!\.{1,2}(?:/|$)|${isTestFile ? `${TEST_RUNNER}$|` : ''}@/shared/kernel(?:/|$)|@/modules/${mod}/domain(?:/|$)).+`,
        isTestFile
          ? 'domain/ tests may import only their own domain/, @/shared/kernel and vitest.'
          : 'domain/ may import only its own domain/ and @/shared/kernel (no I/O, no frameworks, no other layer).',
      ),
      relativeLayers(
        ['application', 'infrastructure', 'presentation', 'shared', 'modules', 'app'],
        'domain/ may not reach other layers or shared/ through relative paths.',
      ),
      relativeStayWithin(
        depth,
        ['domain'],
        'domain/ relative imports must stay inside domain/ (not the module root, its index or another layer).',
      ),
      ...cross,
    );
  return [
    {
      // Everything in the module, including the index and folders without a layer of their own.
      name: `boundaries/${mod}/all`,
      files: [`${base}/**/*.${CODE_EXT}`],
      rules: { 'no-restricted-imports': restrictImports(...cross) },
    },
    ...byDepth('domain', (depth) => domainImports(depth, false), PURE_LAYER_SYNTAX),
    // Unit and integration tests (`x.test.ts`, `x.int.test.ts`) beside the domain code: the same
    // limits plus the test runner. They come later, so they win for test files; the syntax rule
    // (no dynamic loading) is inherited from the objects above.
    ...byDepth('domain', (depth) => domainImports(depth, true), undefined, TEST_FILES, '/tests'),
    ...byDepth(
      'application',
      (depth) =>
        restrictImports(
          aliasLayers(
            mod,
            ['infrastructure', 'presentation'],
            'application/ depends on ports declared in domain/, never on infrastructure/ or presentation/.',
          ),
          relativeLayers(
            ['infrastructure', 'presentation'],
            'application/ depends on ports declared in domain/, never on infrastructure/ or presentation/.',
          ),
          pattern(
            String.raw`^(?:@supabase/|next(?:/|$)|@/shared/db(?:/|$))`,
            'application/ does no I/O: no @supabase/*, next or @/shared/db (use ports from domain/).',
          ),
          relativeStayWithin(
            depth,
            ['domain', 'application'],
            'application/ relative imports may only reach domain/ and application/ (not the module root, its index or another layer).',
          ),
          ...cross,
        ),
      PURE_LAYER_SYNTAX,
    ),
    {
      name: `boundaries/${mod}/infrastructure`,
      files: [`${base}/infrastructure/**/*.${CODE_EXT}`],
      rules: {
        // identity's infrastructure is one of the two places that may use the admin client
        'no-restricted-imports': (mod === 'identity'
          ? restrictImportsAllowingAdminClient
          : restrictImports)(
          aliasLayers(mod, ['presentation'], 'infrastructure/ must not import presentation/.'),
          relativeLayers(['presentation'], 'infrastructure/ must not import presentation/.'),
          ...cross,
        ),
      },
    },
    {
      name: `boundaries/${mod}/presentation`,
      files: [`${base}/presentation/**/*.${CODE_EXT}`],
      rules: { 'no-restricted-imports': restrictImports(...cross) },
    },
  ];
};

const ROUTE_FILES = [`src/app/**/route.${CODE_EXT}`];

/** What src/shared/ may not import: modules, by alias or by relative path. */
const SHARED_PATTERNS = [
  pattern(String.raw`^@/modules(?:/|$)`, 'src/shared/ never imports @/modules/**.'),
  pattern(String.raw`^(?:\./)?(?:\.\./)+modules(?:/|$)`, 'src/shared/ never imports modules/.'),
];

const boundaryConfigs = [
  {
    name: 'boundaries/src',
    files: SRC_FILES,
    rules: { 'no-restricted-imports': restrictImports() },
  },
  ...MODULES.flatMap(moduleLayerConfigs),
  {
    name: 'boundaries/shared',
    files: [`src/shared/**/*.${CODE_EXT}`],
    rules: { 'no-restricted-imports': restrictImports(...SHARED_PATTERNS) },
  },
  {
    // the rate limiter is the other place that may use the admin client (`rate_limit_hit`)
    name: 'boundaries/shared/rate-limit',
    files: [`src/shared/http/rate-limit/**/*.${CODE_EXT}`],
    rules: { 'no-restricted-imports': restrictImportsAllowingAdminClient(...SHARED_PATTERNS) },
  },
  {
    name: 'boundaries/route',
    files: ROUTE_FILES,
    rules: {
      'no-restricted-imports': restrictImports(
        // Allow-only: the handler file of a module's presentation layer.
        pattern(
          String.raw`^(?!@/modules/[^/]+/presentation/[^/]+\.handler$).+`,
          'route.ts may import ONLY "@/modules/<module>/presentation/<name>.handler" (ADR 0005); no @supabase/*, @/shared/db or other layers.',
        ),
      ),
      'no-restricted-syntax': [
        'error',
        ...FORBIDDEN_SYNTAX,
        ...DYNAMIC_LOADING.map((rule) => ({
          ...rule,
          message: `route.ts only re-exports the handler. ${rule.message}`,
        })),
      ],
    },
  },
];

// ------------------------------------------------------------------- main config ----

/**
 * @param {{ typeAware?: boolean }} [options] `typeAware: false` is for linting virtual files
 * (tests/lint/eslint-boundaries.test.ts); the real run keeps type-aware rules on.
 */
export function createConfig({ typeAware = true } = {}) {
  return defineConfig([
    globalIgnores([
      '.next/',
      'node_modules/',
      'venv/',
      'coverage/',
      '.claude/',
      'supabase/',
      'src/shared/db/database.types.ts',
      'next-env.d.ts',
    ]),
    js.configs.recommended,
    {
      files: ['**/*.{ts,tsx,mts,cts}'],
      extends: typeAware
        ? [tseslint.configs.recommendedTypeChecked]
        : [tseslint.configs.recommended],
      languageOptions: {
        globals: { ...globals.node },
        ...(typeAware
          ? { parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname } }
          : {}),
      },
      rules: {
        '@typescript-eslint/no-explicit-any': 'error',
        '@typescript-eslint/consistent-type-imports': [
          'error',
          { prefer: 'type-imports', fixStyle: 'separate-type-imports' },
        ],
        '@typescript-eslint/no-unused-vars': [
          'error',
          { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' },
        ],
        ...(typeAware ? { '@typescript-eslint/no-floating-promises': 'error' } : {}),
      },
    },
    {
      files: ['**/*.{js,mjs,cjs}'],
      languageOptions: { globals: { ...globals.node } },
      extends: [tseslint.configs.disableTypeChecked],
    },
    {
      name: 'src/rules',
      files: SRC_FILES,
      plugins: { '@next/next': nextPlugin },
      rules: {
        ...nextPlugin.configs.recommended.rules,
        // API-only app: there is no pages/ directory for this rule to inspect.
        '@next/next/no-html-link-for-pages': 'off',
        'no-console': 'error',
        'no-restricted-syntax': ['error', ...FORBIDDEN_SYNTAX],
      },
    },
    {
      name: 'scripts/rules',
      files: ['scripts/**/*.ts'],
      rules: { 'no-restricted-syntax': ['error', ...FORBIDDEN_SYNTAX] },
    },
    ...boundaryConfigs,
  ]);
}

export default createConfig();
