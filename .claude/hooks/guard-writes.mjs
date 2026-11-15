#!/usr/bin/env node
// PreToolUse (Write|Edit|MultiEdit|NotebookEdit)
// Bloqueia, antes de gravar:
//   1. arquivos .env* com valores reais (só .env.example é permitido);
//   2. edição de migration que já está na main (migrations são imutáveis);
//   3. conteúdo novo com cara de segredo (chaves, JWT, PEM, URL de banco com senha, NEXT_PUBLIC_ secreto).
// A raiz do projeto vem do git da pasta do arquivo (funciona em worktrees de subagentes, ver lib.mjs).
// A checagem "já está na main" lê as refs do repositório, que as worktrees compartilham.
// Exit 2 = bloqueia e explica ao Claude. Erro interno = exit 1 (avisa, não bloqueia).
import path from 'node:path';
import { block, failOpen, git, projectDir, readHookInput, relativeToProject } from './lib.mjs';

const HOOK = 'guard-writes';
const MAIN_REFS = ['origin/main', 'main'];
const MIN_SECRET_ENTROPY_BITS = 3.5;

const SECRET_PATTERNS = [
  { name: 'Supabase secret key (sb_secret_…)', re: /sb_secret_[A-Za-z0-9_-]{16,}/ },
  { name: 'JWT', re: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { name: 'chave privada PEM', re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  {
    name: 'URL de banco com senha',
    re: /postgres(?:ql)?:\/\/[^:\s/@]+:([^@\s]+)@([^\s/:]+)/,
    // A URL padrão do Supabase local (postgres:postgres@127.0.0.1) é pública e permitida.
    isSecret: (m) => !(m[1] === 'postgres' && /^(127\.0\.0\.1|localhost)$/.test(m[2])),
  },
  {
    name: 'valor de segredo atribuído a variável',
    re: /\b[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*[:=]\s*["']?([A-Za-z0-9+/_=-]{20,})/,
    isSecret: (m) => looksRandom(m[1]),
  },
  {
    name: 'segredo exposto ao browser (prefixo público do Next.js)',
    re: /NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|SERVICE_ROLE|PRIVATE)/,
  },
];

/** Heurística para não confundir alfabetos e nomes com segredos: entropia alta e sem sequências. */
function looksRandom(value) {
  if (/ABCDEFG|abcdefg|0123456|process\.env/.test(value)) return false;
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    entropy -= p * Math.log2(p);
  }
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/].filter((re) => re.test(value)).length;
  return entropy >= MIN_SECRET_ENTROPY_BITS && classes >= 2;
}

function newContent(toolName, toolInput) {
  switch (toolName) {
    case 'Write':
      return toolInput.content ?? '';
    case 'Edit':
      return toolInput.new_string ?? '';
    case 'MultiEdit':
      return (toolInput.edits ?? []).map((e) => e.new_string ?? '').join('\n');
    case 'NotebookEdit':
      return toolInput.new_source ?? '';
    default:
      return '';
  }
}

function existsOnMain(root, rel) {
  for (const ref of MAIN_REFS) {
    try {
      git(root, ['cat-file', '-e', `${ref}:${rel}`]);
      return true;
    } catch {
      // ref inexistente ou arquivo ausente nessa ref: tenta a próxima
    }
  }
  return false;
}

try {
  const input = readHookInput();
  const toolInput = input.tool_input ?? {};
  const target = toolInput.file_path ?? toolInput.notebook_path;
  const root = projectDir(input, target);
  const rel = relativeToProject(root, target);
  const base = target ? path.basename(target) : '';

  // 1. .env reais
  if (/^\.env(\..+)?$/.test(base) && base !== '.env.example') {
    block(
      `[${HOOK}] Bloqueado: "${base}" guarda valores reais e não pode ser escrito pelo agente. ` +
        'Peça ao usuário para editar manualmente. Só .env.example (placeholders vazios) é versionado.',
    );
  }

  // 2. migrations imutáveis
  if (rel && /^supabase\/migrations\/[^/]+\.sql$/.test(rel) && existsOnMain(root, rel)) {
    block(
      `[${HOOK}] Bloqueado: ${rel} já está na main e migrations são imutáveis. ` +
        'Crie uma nova migration com `pnpm db:new <nome>` que corrija o problema (skill new-migration).',
    );
  }

  // 3. segredos no conteúdo novo
  const content = newContent(input.tool_name, toolInput);
  for (const pattern of SECRET_PATTERNS) {
    const match = content.match(pattern.re);
    if (match && (!pattern.isSecret || pattern.isSecret(match))) {
      block(
        `[${HOOK}] Bloqueado: o conteúdo para ${rel ?? target} parece conter ${pattern.name}. ` +
          'Segredos ficam só em variáveis de ambiente (.env.local / Vercel), nunca no código, docs ou testes. ' +
          'Use process.env via src/shared/config/env.ts. Se for falso positivo, explique ao usuário.',
      );
    }
  }

  process.exit(0);
} catch (error) {
  failOpen(HOOK, error);
}
