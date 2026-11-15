// Utilitários compartilhados pelos hooks do projeto (sem dependências externas).
import { readFileSync } from 'node:fs';
import path from 'node:path';

/** Lê e faz o parse do JSON recebido no stdin. Devolve {} se vier vazio. */
export function readHookInput() {
  const raw = readFileSync(0, 'utf8');
  return raw.trim() ? JSON.parse(raw) : {};
}

/** Raiz do projeto: variável do Claude Code, depois o cwd do evento, depois o processo. */
export function projectDir(input) {
  return process.env.CLAUDE_PROJECT_DIR || input.cwd || process.cwd();
}

/** Caminho relativo à raiz, com "/" (ou null se o arquivo estiver fora do projeto). */
export function relativeToProject(root, filePath) {
  if (!filePath) return null;
  const abs = path.resolve(root, filePath);
  const rel = path.relative(root, abs).split(path.sep).join('/');
  return rel.startsWith('..') || path.isAbsolute(rel) ? null : rel;
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
