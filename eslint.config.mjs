// @ts-check
// Flat config. `createConfig` is exported so tests/lint/eslint-boundaries.test.ts exercises the
// REAL boundary rules (with `typeAware: false`, because virtual files are not in the TS project).
import js from '@eslint/js';
import nextPlugin from '@next/eslint-plugin-next';
import { defineConfig, globalIgnores } from 'eslint/config';
import globals from 'globals';
import tseslint from 'typescript-eslint';

const MODULES = ['identity', 'tracking'];
/** Modules a module may not import at all (not even through the index). */
const FORBIDDEN_MODULE_DEPS = { tracking: ['identity'] };

const SRC_FILES = ['src/**/*.{ts,tsx}'];
const NEXT_HEADERS = {
  name: 'next/headers',
  message:
    'Do not use next/headers: the pipeline reads NextRequest and writes NextResponse (spec §3.3).',
};

// ------------------------------------------------------------ no-restricted-syntax ----

const POSTGREST_FILTER = '[callee.property.name=/^(or|filter|textSearch)$/]';
const POSTGREST_MESSAGE =
  'Interpolated/concatenated input in a PostgREST filter allows injection (spec §3.8). ' +
  'Use .eq/.in/.ilike with a plain value or an RPC.';

const FORBIDDEN_SYNTAX = [
  {
    selector: `CallExpression[callee.type='MemberExpression']${POSTGREST_FILTER} > TemplateLiteral.arguments[expressions.length>0]`,
    message: POSTGREST_MESSAGE,
  },
  {
    selector: `CallExpression[callee.type='MemberExpression']${POSTGREST_FILTER} > BinaryExpression[operator='+'].arguments`,
    message: POSTGREST_MESSAGE,
  },
  {
    selector:
      "CallExpression[callee.property.name='getSession']:matches([callee.object.property.name='auth'], [callee.object.name='auth'])",
    message:
      'auth.getSession() does not validate the JWT on the server. Use getClaims()/getUser() through the PrincipalResolver.',
  },
];

// ------------------------------------------------------------ no-restricted-imports ----

/** @param {string} message @param {string} regex */
const pattern = (regex, message) => ({ regex, message });

/**
 * no-restricted-imports options. `next/headers` is forbidden everywhere in src/. Later config
 * objects REPLACE earlier ones for the same rule, so each layer lists its full set.
 * @param {...{ regex: string, message: string }} patterns
 */
const restrictImports = (...patterns) => ['error', { paths: [NEXT_HEADERS], patterns }];

const alt = (/** @type {string[]} */ names) => names.join('|');

/** `@/modules/<mod>/<layer>` imports. */
const aliasLayers = (/** @type {string} */ mod, /** @type {string[]} */ layers, message) =>
  pattern(String.raw`^@/modules/${mod}/(?:${alt(layers)})(?:/|$)`, message);

/** Relative imports (`../infrastructure/x`, `./a/presentation/y`) that land in one of the folders. */
const relativeLayers = (/** @type {string[]} */ layers, message) =>
  pattern(String.raw`^\.{1,2}/(?:.*/)?(?:${alt(layers)})(?:/|$)`, message);

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
            String.raw`^(?:\.\./)+(?:modules/)?(?:${alt(others)})(?:/|$)`,
            'Do not reach into another module with relative paths; use its index through the "@/modules/<name>" alias.',
          ),
        ]
      : []),
  ];
};

/** Rules for src/modules/<mod>/<layer>/**. */
const moduleLayerConfigs = (/** @type {string} */ mod) => {
  const base = `src/modules/${mod}`;
  const cross = crossModulePatterns(mod);
  return [
    {
      name: `boundaries/${mod}/domain`,
      files: [`${base}/domain/**/*.ts`],
      rules: {
        'no-restricted-imports': restrictImports(
          // Allow-only: relative paths inside domain, own domain via alias, shared/kernel.
          pattern(
            String.raw`^(?!\.{1,2}(?:/|$)|@/shared/kernel(?:/|$)|@/modules/${mod}/domain(?:/|$)).+`,
            'domain/ may import only its own domain/ and @/shared/kernel (no I/O, no frameworks, no other layer).',
          ),
          relativeLayers(
            ['application', 'infrastructure', 'presentation', 'shared', 'modules', 'app'],
            'domain/ may not reach other layers or shared/ through relative paths.',
          ),
          ...cross,
        ),
      },
    },
    {
      name: `boundaries/${mod}/application`,
      files: [`${base}/application/**/*.ts`],
      rules: {
        'no-restricted-imports': restrictImports(
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
          ...cross,
        ),
      },
    },
    {
      name: `boundaries/${mod}/infrastructure`,
      files: [`${base}/infrastructure/**/*.ts`],
      rules: {
        'no-restricted-imports': restrictImports(
          aliasLayers(mod, ['presentation'], 'infrastructure/ must not import presentation/.'),
          relativeLayers(['presentation'], 'infrastructure/ must not import presentation/.'),
          ...cross,
        ),
      },
    },
    {
      name: `boundaries/${mod}/presentation`,
      files: [`${base}/presentation/**/*.ts`],
      rules: { 'no-restricted-imports': restrictImports(...cross) },
    },
    {
      name: `boundaries/${mod}/index`,
      files: [`${base}/*.ts`],
      rules: { 'no-restricted-imports': restrictImports(...cross) },
    },
  ];
};

const boundaryConfigs = [
  {
    name: 'boundaries/src',
    files: SRC_FILES,
    rules: { 'no-restricted-imports': restrictImports() },
  },
  ...MODULES.flatMap(moduleLayerConfigs),
  {
    name: 'boundaries/shared',
    files: ['src/shared/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': restrictImports(
        pattern(String.raw`^@/modules(?:/|$)`, 'src/shared/ never imports @/modules/**.'),
        pattern(String.raw`^(?:\.\./)+modules(?:/|$)`, 'src/shared/ never imports modules/.'),
      ),
    },
  },
  {
    name: 'boundaries/route',
    files: ['src/app/**/route.{ts,tsx}'],
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
        {
          selector: 'ImportExpression',
          message: 'route.ts only re-exports the handler; dynamic import() is not allowed.',
        },
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
