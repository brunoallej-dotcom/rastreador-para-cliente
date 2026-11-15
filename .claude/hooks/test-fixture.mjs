// Apoio dos testes dos hooks (node:test, sem dependências). Não é um teste: o glob é *.test.mjs.
// Monta, em diretórios temporários, um repositório git descartável com commit inicial na branch main e uma
// worktree dele em outro caminho (ou aninhada em .claude/worktrees/, como nos subagentes do Claude Code).
import { execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const HOOKS_DIR = path.dirname(fileURLToPath(import.meta.url));
export const REPO_ROOT = path.resolve(HOOKS_DIR, '..', '..');

const GIT_LOCATION_ENV = ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR', 'GIT_PREFIX'];

/** Ambiente isolado: sem variáveis de localização do git e sem a configuração global/de sistema do usuário. */
export function cleanEnv(extra = {}) {
  const env = { ...process.env };
  for (const name of GIT_LOCATION_ENV) delete env[name];
  env.GIT_CONFIG_GLOBAL = os.devNull;
  env.GIT_CONFIG_NOSYSTEM = '1';
  env.GIT_TERMINAL_PROMPT = '0';
  return { ...env, ...extra };
}

// Os testes em processo (lib.test.mjs) chamam o git do próprio lib.mjs com process.env.
for (const name of GIT_LOCATION_ENV) delete process.env[name];

/** Roda o git em `cwd` e devolve o stdout. */
export function git(cwd, ...args) {
  return execFileSync('git', args, { cwd, env: cleanEnv(), encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

/** Grava um arquivo criando as pastas que faltam. */
export function write(file, content = '') {
  mkdirSync(path.dirname(file), { recursive: true });
  writeFileSync(file, content);
  return file;
}

const INITIAL_MIGRATION = 'supabase/migrations/20260101000000_init.sql';
const INITIAL_MIGRATION_SQL = [
  'CREATE TABLE public.items (id uuid PRIMARY KEY);',
  'ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;',
  '',
].join('\n');

/**
 * Cria `<tmp>/main-checkout` (branch main, 1 commit com README, NOTES.md e uma migration) e uma worktree
 * `feat/wave-x` dele. `nested: true` põe a worktree em `<main>/.claude/worktrees/wave-x`; senão, num
 * caminho fora do repositório. Devolve os caminhos e `cleanup()`.
 */
export function createFixture({ nested = false } = {}) {
  const base = mkdtempSync(path.join(os.tmpdir(), 'hooks-test-'));
  const main = path.join(base, 'main-checkout');
  const worktree = nested
    ? path.join(main, '.claude', 'worktrees', 'wave-x')
    : path.join(base, 'worktrees', 'wave-x');

  mkdirSync(main, { recursive: true });
  git(main, 'init', '--quiet', '--initial-branch=main');
  git(main, 'config', 'user.name', 'Hooks Test');
  git(main, 'config', 'user.email', 'hooks-test@example.invalid');
  git(main, 'config', 'commit.gpgsign', 'false');
  write(path.join(main, 'README.md'), '# fixture\n');
  write(path.join(main, 'NOTES.md'), '# Notes\n\n## Status atual\n\n- status-da-main\n\n## Log\n');
  write(path.join(main, INITIAL_MIGRATION), INITIAL_MIGRATION_SQL);
  git(main, 'add', '-A');
  git(main, 'commit', '--quiet', '-m', 'chore: initial commit');

  mkdirSync(path.dirname(worktree), { recursive: true });
  git(main, 'worktree', 'add', '--quiet', '-b', 'feat/wave-x', worktree);

  return {
    base,
    main,
    worktree,
    /** Caminho real (sem symlinks) da worktree: é o que o `git rev-parse --show-toplevel` devolve. */
    realWorktree: realpathSync(worktree),
    initialMigration: INITIAL_MIGRATION,
    cleanup() {
      rmSync(base, { recursive: true, force: true });
    },
  };
}

/** Instala em `<root>/node_modules/.bin/prettier` um falso prettier que grava um marcador ao ser chamado. */
export function installFakePrettier(root, markerFile) {
  const bin = path.join(root, 'node_modules', '.bin', 'prettier');
  write(
    bin,
    `#!${process.execPath}\nrequire('node:fs').appendFileSync(${JSON.stringify(markerFile)}, process.argv.slice(2).join(' ') + '\\n');\n`,
  );
  chmodSync(bin, 0o755);
  return bin;
}

/** Executa um hook de verdade, com o JSON no stdin como o Claude Code faz. */
export function runHook(script, payload, { projectDir, cwd = projectDir, rawInput } = {}) {
  const env = cleanEnv(projectDir === undefined ? {} : { CLAUDE_PROJECT_DIR: projectDir });
  if (projectDir === undefined) delete env.CLAUDE_PROJECT_DIR;
  const result = spawnSync(process.execPath, [path.join(HOOKS_DIR, script)], {
    cwd,
    env,
    input: rawInput ?? JSON.stringify(payload),
    encoding: 'utf8',
    timeout: 30000,
  });
  return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}
