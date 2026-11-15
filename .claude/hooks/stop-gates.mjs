#!/usr/bin/env node
// Stop e SubagentStop (subagentes terminam com SubagentStop, não com Stop)
// Impede encerrar o turno quando a árvore de trabalho tem:
//   (a) migration nova ou alterada sem nenhum teste pgTAP novo ou alterado;
//   (b) route.ts novo cujo path não existe em contracts/openapi.v1.yaml.
// Bloqueia só uma vez por sequência (respeita stop_hook_active), para o Claude poder explicar e parar.
// A árvore checada é a do `cwd` do evento (a worktree do subagente, quando houver), não o checkout principal.
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { git, projectDir, readHookInput } from './lib.mjs';

const GIT_TIMEOUT_MS = 5000;
const CONTRACT = 'contracts/openapi.v1.yaml';

function changedFiles(root) {
  const out = git(root, ['status', '--porcelain=v1', '-uall'], { timeout: GIT_TIMEOUT_MS });
  return out
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const status = line.slice(0, 2);
      const file = line.slice(3).split(' -> ').pop().replace(/^"|"$/g, '');
      return { status, file };
    });
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

  let files;
  try {
    files = changedFiles(root);
  } catch {
    process.exit(0); // fora de um repositório git: nada a checar
  }

  const reasons = [];

  const migrations = files.filter((f) => /^supabase\/migrations\/.+\.sql$/.test(f.file) && !f.status.includes('D'));
  const dbTests = files.filter((f) => /^supabase\/tests\/.+\.sql$/.test(f.file));
  if (migrations.length > 0 && dbTests.length === 0) {
    reasons.push(
      `Migrations alteradas sem teste pgTAP correspondente: ${migrations.map((f) => f.file).join(', ')}. ` +
        'Adicione ou atualize supabase/tests/*.test.sql (skill tenant-isolation-tests) ou explique ao usuário por que não se aplica.',
    );
  }

  const contractPath = path.join(root, CONTRACT);
  const contract = existsSync(contractPath) ? readFileSync(contractPath, 'utf8') : '';
  const newRoutes = files.filter((f) => (f.status === '??' || f.status.includes('A')) && routeToContractPath(f.file));
  const undocumented = newRoutes
    .map((f) => ({ file: f.file, apiPath: routeToContractPath(f.file) }))
    .filter(({ apiPath }) => !contract.includes(`\n  ${apiPath}:`));
  if (undocumented.length > 0) {
    reasons.push(
      `Route Handlers sem path no contrato (${CONTRACT}): ${undocumented.map((u) => `${u.file} → ${u.apiPath}`).join(', ')}. ` +
        'Contrato primeiro: atualize o OpenAPI (com bump de versão) e a spec, ou remova a rota.',
    );
  }

  if (reasons.length > 0) {
    process.stdout.write(`${JSON.stringify({ decision: 'block', reason: `[stop-gates] ${reasons.join(' ')}` })}\n`);
  }
  process.exit(0);
} catch (error) {
  process.stderr.write(`[stop-gates] erro interno ignorado: ${error?.message ?? error}\n`);
  process.exit(0);
}
