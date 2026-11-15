#!/usr/bin/env node
// Stop e SubagentStop (subagentes terminam com SubagentStop, não com Stop)
// Impede encerrar o turno quando o trabalho tem:
//   (a) migration nova ou alterada sem nenhum teste pgTAP novo ou alterado;
//   (b) route.ts novo cujo path não existe em contracts/openapi.v1.yaml.
// O trabalho é a UNIÃO de duas fontes, para que commitar antes de parar não esconda pendências:
//   1. `git status --porcelain` (árvore de trabalho e índice, inclusive arquivos não rastreados);
//   2. os arquivos alterados na branch desde o merge-base com a main: `git diff --name-status <base>..HEAD`
//      (base = merge-base com `main`; se não existir, com `origin/main`; se nenhuma existir, só a árvore).
// Um arquivo que não existe mais na árvore (apagado) não conta como migration, teste nem rota.
// Bloqueia só uma vez por sequência (respeita stop_hook_active), para o Claude poder explicar e parar.
// A árvore checada é a do `cwd` do evento (a worktree do subagente, quando houver), não o checkout principal.
// Falhas do git: "não é um repositório" sai em silêncio (exit 0); timeout ou outra falha nunca é um "passou"
// silencioso: vira aviso no stderr com exit 1 (não bloqueia, mas aparece para o usuário). Se o git falhar só
// na parte da branch, a checagem segue com o que conseguiu (a árvore) e o aviso acompanha o resultado.
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { existingMainRefs, gitFailureText, gitResult, projectDir, readHookInput } from './lib.mjs';

const HOOK = 'stop-gates';
const GIT_STATUS_TIMEOUT_MS = 5000;
const GIT_BRANCH_TIMEOUT_MS = 3000;
const CONTRACT = 'contracts/openapi.v1.yaml';
/** Código de saída do `git merge-base` quando não há ancestral comum (não é uma falha). */
const MERGE_BASE_NONE_STATUS = 1;

/** Interpreta `git status --porcelain=v1 -z -uall`: [{ file, added }] (renomeação/cópia: devolve o destino). */
function parseStatus(out) {
  const tokens = out.split('\0').filter(Boolean);
  const entries = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const token = tokens[i];
    const status = token.slice(0, 2);
    const file = token.slice(3);
    if (/[RC]/.test(status)) i += 1; // o próximo token é o caminho de origem
    entries.push({ file, added: status === '??' || status.includes('A') });
  }
  return entries;
}

/** Interpreta `git diff --name-status --no-renames -z`: pares status, caminho. */
function parseNameStatus(out) {
  const tokens = out.split('\0').filter(Boolean);
  const entries = [];
  for (let i = 0; i + 1 < tokens.length; i += 2) {
    entries.push({ file: tokens[i + 1], added: tokens[i] === 'A' });
  }
  return entries;
}

/**
 * Arquivos alterados na branch desde o merge-base com a main. Devolve { entries, warning }:
 * sem main (nem origin/main), sem ancestral comum ou sem HEAD, a lista é vazia e sem aviso; timeout ou
 * outra falha do git gera `warning`.
 */
function branchChanges(root) {
  const refs = existingMainRefs(root);
  if (!refs.ok) return { entries: [], warning: `não localizei a main (${gitFailureText(refs)})` };

  let base = null;
  for (const ref of refs.refs) {
    const mb = gitResult(root, ['merge-base', ref, 'HEAD'], { timeout: GIT_BRANCH_TIMEOUT_MS });
    if (mb.ok) {
      base = mb.stdout.trim();
      break;
    }
    if (mb.kind === 'failed' && mb.status === MERGE_BASE_NONE_STATUS) continue; // sem ancestral comum
    if (mb.kind === 'failed' && /valid object name HEAD/i.test(mb.stderr)) continue; // repositório sem commits
    return { entries: [], warning: `merge-base com ${ref} falhou (${gitFailureText(mb)})` };
  }
  if (!base) return { entries: [], warning: null };

  const diff = gitResult(root, ['diff', '--name-status', '--no-renames', '-z', `${base}..HEAD`], {
    timeout: GIT_BRANCH_TIMEOUT_MS,
  });
  if (!diff.ok) return { entries: [], warning: `diff da branch falhou (${gitFailureText(diff)})` };
  return { entries: parseNameStatus(diff.stdout), warning: null };
}

/** União das duas fontes, por arquivo: `added` se qualquer fonte o marcou como novo. */
function mergeEntries(...lists) {
  const byFile = new Map();
  for (const list of lists) {
    for (const { file, added } of list) {
      const previous = byFile.get(file);
      byFile.set(file, { file, added: added || (previous?.added ?? false) });
    }
  }
  return [...byFile.values()];
}

/** src/app/api/v1/admin/clients/[clientId]/route.ts → /admin/clients/{clientId} */
function routeToContractPath(file) {
  const m = file.match(/^src\/app\/api\/v1\/(.+)\/route\.tsx?$/);
  if (!m) return null;
  return `/${m[1].replace(/\[([A-Za-z0-9_]+)\]/g, '{$1}')}`;
}

try {
  const input = readHookInput();
  if (input.stop_hook_active) process.exit(0);
  const root = projectDir(input);

  const warnings = [];
  const status = gitResult(root, ['status', '--porcelain=v1', '-z', '-uall'], { timeout: GIT_STATUS_TIMEOUT_MS });
  if (!status.ok) {
    if (status.kind === 'not-repo') process.exit(0); // fora de um repositório git: nada a checar
    process.stderr.write(`[${HOOK}] aviso: checagem não executada em ${root} (${gitFailureText(status)}).\n`);
    process.exit(1);
  }
  const branch = branchChanges(root);
  if (branch.warning) warnings.push(`commits da branch não checados (${branch.warning})`);

  const files = mergeEntries(parseStatus(status.stdout), branch.entries).filter((f) =>
    existsSync(path.join(root, f.file)),
  );

  const reasons = [];

  const migrations = files.filter((f) => /^supabase\/migrations\/.+\.sql$/.test(f.file));
  const dbTests = files.filter((f) => /^supabase\/tests\/.+\.sql$/.test(f.file));
  if (migrations.length > 0 && dbTests.length === 0) {
    reasons.push(
      `Migrations alteradas sem teste pgTAP correspondente: ${migrations.map((f) => f.file).join(', ')}. ` +
        'Adicione ou atualize supabase/tests/*.test.sql (skill tenant-isolation-tests) ou explique ao usuário por que não se aplica.',
    );
  }

  const contractPath = path.join(root, CONTRACT);
  const contract = existsSync(contractPath) ? readFileSync(contractPath, 'utf8') : '';
  const undocumented = files
    .filter((f) => f.added && routeToContractPath(f.file))
    .map((f) => ({ file: f.file, apiPath: routeToContractPath(f.file) }))
    .filter(({ apiPath }) => !contract.includes(`\n  ${apiPath}:`));
  if (undocumented.length > 0) {
    reasons.push(
      `Route Handlers sem path no contrato (${CONTRACT}): ${undocumented.map((u) => `${u.file} → ${u.apiPath}`).join(', ')}. ` +
        'Contrato primeiro: atualize o OpenAPI (com bump de versão) e a spec, ou remova a rota.',
    );
  }

  for (const warning of warnings) process.stderr.write(`[${HOOK}] aviso: ${warning}.\n`);
  if (reasons.length > 0) {
    process.stdout.write(`${JSON.stringify({ decision: 'block', reason: `[${HOOK}] ${reasons.join(' ')}` })}\n`);
    process.exit(0);
  }
  process.exit(warnings.length > 0 ? 1 : 0);
} catch (error) {
  process.stderr.write(`[${HOOK}] erro interno ignorado: ${error?.message ?? error}\n`);
  process.exit(0);
}
