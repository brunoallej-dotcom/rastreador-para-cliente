// Utilitários compartilhados pelos hooks do projeto (sem dependências externas).
//
// Raiz do projeto: resolvida pelo git, nunca só por CLAUDE_PROJECT_DIR. Subagentes rodam em worktrees
// (ex.: <repo>/.claude/worktrees/<nome> ou outro caminho) enquanto CLAUDE_PROJECT_DIR continua apontando
// para o checkout principal; com essa raiz, caminhos da worktree não casariam com ^src/ nem ^supabase/ e
// as checagens seriam puladas sem aviso. Por isso a raiz é `git rev-parse --show-toplevel` a partir da
// pasta do arquivo editado (hooks de Write/Edit) ou do `cwd` do evento (Stop, SubagentStop, SessionStart).
import { execFileSync } from 'node:child_process';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';

const GIT_TIMEOUT_MS = 3000;
const GIT_MAX_BUFFER_BYTES = 16 * 1024 * 1024;
/** Variáveis que fazem o git ignorar o diretório de trabalho (ex.: hook disparado por outro hook do git). */
const GIT_LOCATION_ENV = [
  'GIT_DIR',
  'GIT_WORK_TREE',
  'GIT_INDEX_FILE',
  'GIT_COMMON_DIR',
  'GIT_PREFIX',
  'GIT_OBJECT_DIRECTORY',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
];

/** Lê e faz o parse do JSON recebido no stdin. Devolve {} se vier vazio. */
export function readHookInput() {
  const raw = readFileSync(0, 'utf8');
  return raw.trim() ? JSON.parse(raw) : {};
}

/** Executa o git em `cwd` (sem shell) e devolve o stdout. Lança se o git falhar ou estourar o timeout. */
export function git(cwd, args, { timeout = GIT_TIMEOUT_MS } = {}) {
  const env = { ...process.env };
  for (const name of GIT_LOCATION_ENV) delete env[name];
  return execFileSync('git', args, {
    cwd,
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    timeout,
    maxBuffer: GIT_MAX_BUFFER_BYTES,
  });
}

/** Ancestral existente mais próximo (inclusive o próprio caminho) que seja um diretório. */
function nearestExistingDir(start) {
  let dir = path.resolve(start);
  for (;;) {
    try {
      if (statSync(dir).isDirectory()) return dir;
    } catch {
      // não existe (ou não é acessível): sobe um nível
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

/** realpath tolerante: resolve symlinks do trecho que existe e acrescenta o resto (arquivo ainda não criado). */
function realpathLoose(target) {
  const abs = path.resolve(target);
  const tail = [];
  let current = abs;
  for (;;) {
    let real = null;
    try {
      real = realpathSync(current);
    } catch {
      // inexistente: guarda o nome e sobe um nível
    }
    if (real !== null) return path.join(real, ...tail.reverse());
    const parent = path.dirname(current);
    if (parent === current) return abs;
    tail.push(path.basename(current));
    current = parent;
  }
}

/**
 * Raiz do work tree git que contém `start` (um diretório; se não existir, usa o ancestral existente mais
 * próximo, pois o Write pode criar pastas novas). Devolve null fora de um repositório ou se o git falhar.
 */
export function gitToplevel(start) {
  const dir = nearestExistingDir(start);
  if (!dir) return null;
  try {
    const top = git(dir, ['rev-parse', '--show-toplevel']).trim();
    return top ? path.resolve(top) : null;
  } catch {
    return null;
  }
}

/**
 * Raiz do projeto para este evento.
 * - Com `targetFile` (hooks de Write/Edit): raiz git da pasta do arquivo, mesmo que ele esteja numa worktree.
 * - Sem `targetFile` (Stop, SubagentStop, SessionStart): raiz git do `cwd` do evento.
 * Só se o git não resolver (fora de um repositório, git ausente) cai em CLAUDE_PROJECT_DIR, `cwd` e process.cwd().
 */
export function projectDir(input = {}, targetFile) {
  const fallback = process.env.CLAUDE_PROJECT_DIR || input.cwd || process.cwd();
  const base = input.cwd || process.env.CLAUDE_PROJECT_DIR || process.cwd();
  const start = targetFile ? path.dirname(path.resolve(base, targetFile)) : base;
  return gitToplevel(start) ?? fallback;
}

function relativeInside(root, abs) {
  const rel = path.relative(root, abs).split(path.sep).join('/');
  return rel === '' || rel.startsWith('..') || path.isAbsolute(rel) ? null : rel;
}

/**
 * Caminho relativo à raiz, com "/" (ou null se o arquivo estiver fora do projeto). O git devolve a raiz já
 * sem symlinks; se o caminho do arquivo passar por um symlink, compara de novo pelos caminhos reais.
 */
export function relativeToProject(root, filePath) {
  if (!filePath) return null;
  const abs = path.resolve(root, filePath);
  return relativeInside(root, abs) ?? relativeInside(realpathLoose(root), realpathLoose(abs));
}

/** Encerra bloqueando (exit 2): a mensagem vai para o Claude via stderr. */
export function block(message) {
  process.stderr.write(`${message.trim()}\n`);
  process.exit(2);
}

/** Erro interno do hook: avisa o usuário (exit 1, não bloqueia) em vez de travar o trabalho. */
export function failOpen(hookName, error) {
  process.stderr.write(`[${hookName}] erro interno ignorado: ${error?.message ?? error}\n`);
  process.exit(1);
}

/** Número da linha (1-based) de um índice no texto. */
export function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i += 1) if (text[i] === '\n') line += 1;
  return line;
}
