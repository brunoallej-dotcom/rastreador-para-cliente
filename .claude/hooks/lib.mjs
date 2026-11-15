// Utilitários compartilhados pelos hooks do projeto (sem dependências externas).
//
// Raiz do projeto: resolvida pelo git, nunca só por CLAUDE_PROJECT_DIR. Subagentes rodam em worktrees
// (ex.: <repo>/.claude/worktrees/<nome> ou outro caminho) enquanto CLAUDE_PROJECT_DIR continua apontando
// para o checkout principal; com essa raiz, caminhos da worktree não casariam com ^src/ nem ^supabase/ e
// as checagens seriam puladas sem aviso. Por isso a raiz é `git rev-parse --show-toplevel` a partir da
// pasta do arquivo editado (hooks de Write/Edit) ou do `cwd` do evento (Stop, SubagentStop, SessionStart).
// Essa raiz só vale se pertencer ao MESMO repositório de CLAUDE_PROJECT_DIR (mesmo `--git-common-dir`): uma
// worktree vinculada compartilha o diretório comum; um `.git` aninhado (ex.: `git init` em <repo>/src) não, e
// sequestraria a raiz, deixando os caminhos relativos errados e as checagens de src/ e supabase/ sem efeito.
import { execFileSync } from 'node:child_process';
import { readFileSync, realpathSync, statSync } from 'node:fs';
import path from 'node:path';

const GIT_TIMEOUT_MS = 3000;
/** Teto opcional de timeout do git, em ms (só encurta; usado pelos testes para simular travamento sem esperar). */
const GIT_TIMEOUT_CAP_ENV = 'HOOKS_GIT_TIMEOUT_MS';
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
  // LC_ALL=C fixa as mensagens do git em inglês: é assim que se distingue "não é um repositório" de outras falhas.
  env.LC_ALL = 'C';
  const cap = Number(process.env[GIT_TIMEOUT_CAP_ENV]);
  if (cap > 0) timeout = Math.min(timeout, cap);
  return execFileSync('git', args, {
    cwd,
    env,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout,
    maxBuffer: GIT_MAX_BUFFER_BYTES,
  });
}

/**
 * Classifica uma falha do git (erro lançado por `git()`):
 *   timeout     → estourou o tempo limite;
 *   unavailable → o executável git não existe;
 *   not-repo    → "not a git repository" (fora de um repositório);
 *   failed      → qualquer outra falha (índice corrompido, "dubious ownership", ref inválida…).
 * Devolve também o código de saída (ou null) e o stderr do git.
 */
export function describeGitError(error) {
  const stderr = String(error?.stderr ?? '').trim();
  let kind = 'failed';
  if (error?.code === 'ETIMEDOUT' || error?.killed === true) kind = 'timeout';
  else if (error?.code === 'ENOENT') kind = 'unavailable';
  else if (/not a git repository/i.test(stderr)) kind = 'not-repo';
  return { kind, status: typeof error?.status === 'number' ? error.status : null, stderr };
}

/** Como `git()`, mas sem lançar: devolve { ok: true, stdout } ou { ok: false, kind, status, stderr }. */
export function gitResult(cwd, args, options) {
  try {
    return { ok: true, stdout: git(cwd, args, options) };
  } catch (error) {
    return { ok: false, ...describeGitError(error) };
  }
}

/** Frase curta para mensagens ao usuário/agente sobre uma falha de `gitResult`. */
export function gitFailureText(result) {
  switch (result.kind) {
    case 'timeout':
      return 'git estourou o tempo limite';
    case 'unavailable':
      return 'git não está disponível';
    case 'not-repo':
      return 'não é um repositório git';
    default:
      return `git falhou${result.status === null ? '' : ` (código ${result.status})`}`;
  }
}

/** Refs que representam a main, na ordem de preferência (a local primeiro). */
const MAIN_REF_NAMES = ['refs/heads/main', 'refs/remotes/origin/main'];

/**
 * Quais refs da main existem no repositório de `cwd` (uma única chamada ao git). Devolve
 * { ok: true, refs } (refs na ordem de preferência; vazio se nenhuma existir) ou o resultado de falha do git.
 */
export function existingMainRefs(cwd) {
  const result = gitResult(cwd, ['for-each-ref', '--format=%(refname)', ...MAIN_REF_NAMES]);
  if (!result.ok) return result;
  const found = new Set(result.stdout.split('\n').map((l) => l.trim()).filter(Boolean));
  return { ok: true, refs: MAIN_REF_NAMES.filter((ref) => found.has(ref)) };
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
export function realpathLoose(target) {
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

/** Diretório comum do git (realpath) do repositório que contém `dir`; null se não for resolvível. */
function gitCommonDir(dir) {
  const start = nearestExistingDir(dir);
  if (!start) return null;
  try {
    const out = git(start, ['rev-parse', '--git-common-dir']).trim();
    return out ? realpathSync(path.resolve(start, out)) : null;
  } catch {
    return null;
  }
}

/**
 * Os dois diretórios pertencem ao mesmo repositório git? Compara `git rev-parse --git-common-dir` (com
 * realpath): checkout principal e worktrees vinculadas compartilham o diretório comum; um repositório
 * aninhado ou de fora, não. Se qualquer lado não resolver, devolve false.
 */
export function sameRepository(dirA, dirB) {
  const a = gitCommonDir(dirA);
  return a !== null && a === gitCommonDir(dirB);
}

/** O caminho tem um segmento `.git` (`/.git/…` ou terminado em `/.git`)? Sem diferenciar maiúsculas. */
export function hasGitSegment(target) {
  return /(^|[\\/])\.git([\\/]|$)/i.test(path.resolve(target));
}

/**
 * Raiz do projeto para este evento.
 * - Com `targetFile` (hooks de Write/Edit): raiz git da pasta do arquivo, mesmo que ele esteja numa worktree.
 * - Sem `targetFile` (Stop, SubagentStop, SessionStart): raiz git do `cwd` do evento.
 * Com CLAUDE_PROJECT_DIR definida, a raiz git só é aceita se for o próprio CLAUDE_PROJECT_DIR ou de uma
 * worktree do mesmo repositório (ver `sameRepository`). Um repositório aninhado/estranho é pulado: a busca
 * sobe para o repositório que o contém (ex.: `git init` em <worktree>/src → volta a <worktree>), de modo que
 * o `.git` aninhado não sequestra a raiz nem desliga as checagens de src/ e supabase/.
 * Sem CLAUDE_PROJECT_DIR, vale a raiz git mais próxima. Se o git não resolver (fora de um repositório, git
 * ausente) ou nenhuma raiz for aceita, cai em CLAUDE_PROJECT_DIR, `cwd` do evento e process.cwd(), nessa ordem.
 */
export function projectDir(input = {}, targetFile) {
  const envDir = process.env.CLAUDE_PROJECT_DIR;
  const fallback = envDir || input.cwd || process.cwd();
  const base = input.cwd || envDir || process.cwd();
  const start = targetFile ? path.dirname(path.resolve(base, targetFile)) : base;
  let top = gitToplevel(start);
  if (top === null || !envDir) return top ?? fallback;
  const envReal = realpathLoose(envDir);
  while (top !== null) {
    if (top === envReal || sameRepository(top, envDir)) return top;
    const parent = path.dirname(top);
    if (parent === top) break;
    top = gitToplevel(parent);
  }
  return fallback;
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
