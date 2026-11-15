#!/usr/bin/env node
// PostToolUse (Write|Edit|MultiEdit)
// Depois da escrita: formata com Prettier (se instalado) e faz checagens estáticas rápidas:
//   supabase/migrations/*.sql  → RLS, policies, grants, SECURITY DEFINER, REVOKE, SQL dinâmica
//   src/**/*.ts(x)             → secret key, admin client, filtros PostgREST, getSession, console, route.ts fino
//   contracts/openapi*.yaml    → Redocly lint (se instalado)
// Exit 2 = devolve as violações ao Claude para correção imediata. Erro interno = exit 1.
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { block, failOpen, lineOf, projectDir, readHookInput, relativeToProject } from './lib.mjs';

const HOOK = 'post-edit-checks';
const TOOL_TIMEOUT_MS = 45000;
const MAX_OUTPUT_CHARS = 4000;
const PRETTIER_EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.mjs', '.cjs', '.json', '.yaml', '.yml', '.css']);

const SECRET_KEY_ALLOWED = new Set(['src/shared/db/admin-client.ts', 'src/shared/config/env.ts']);
const ADMIN_CLIENT_IMPORTERS = [/^src\/shared\/http\/rate-limit\//, /^src\/modules\/identity\/infrastructure\//];

// ---------------------------------------------------------------- SQL ----

/** Troca comentários por espaços preservando quebras de linha (para manter os números de linha). */
function stripSqlComments(sql) {
  const blank = (s) => s.replace(/[^\n]/g, ' ');
  return sql.replace(/\/\*[\s\S]*?\*\//g, blank).replace(/--[^\n]*/g, blank);
}

/** Separa os corpos $tag$…$tag$ do resto do texto (atributos e DDL), preservando posições. */
function splitDollarBodies(sql) {
  const bodies = [];
  let outside = sql;
  const re = /\$([A-Za-z_]*)\$[\s\S]*?\$\1\$/g;
  outside = sql.replace(re, (m, _tag, offset) => {
    bodies.push({ text: m, index: offset });
    return m.replace(/[^\n]/g, ' ');
  });
  return { outside, bodies };
}

function checkMigration(raw) {
  const problems = [];
  const sql = stripSqlComments(raw);
  const { outside, bodies } = splitDollarBodies(sql);

  // Tabelas em public precisam de RLS.
  for (const m of outside.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?(?:(\w+)\.)?"?(\w+)"?/gi)) {
    const schema = (m[1] ?? 'public').toLowerCase();
    const table = m[2];
    if (schema !== 'public') continue;
    const rls = new RegExp(
      `alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:only\\s+)?(?:public\\.)?"?${table}"?\\s+enable\\s+row\\s+level\\s+security`,
      'i',
    );
    if (!rls.test(outside)) {
      problems.push(`linha ${lineOf(sql, m.index)}: tabela public.${table} sem ENABLE ROW LEVEL SECURITY.`);
    }
  }

  if (/disable\s+row\s+level\s+security/i.test(outside)) {
    problems.push(`linha ${lineOf(sql, outside.search(/disable\s+row\s+level\s+security/i))}: DISABLE ROW LEVEL SECURITY é proibido.`);
  }

  // Statements fora dos corpos de função.
  const statements = [];
  let start = 0;
  for (let i = 0; i <= outside.length; i += 1) {
    if (i === outside.length || outside[i] === ';') {
      statements.push({ text: outside.slice(start, i), index: start });
      start = i + 1;
    }
  }

  for (const st of statements) {
    const text = st.text.trim();
    const at = `linha ${lineOf(sql, st.index + st.text.search(/\S|$/))}`;

    if (/^create\s+policy\b/i.test(text)) {
      const forClause = text.match(/\bfor\s+(select|insert|update|delete|all)\b/i);
      if (!forClause) problems.push(`${at}: policy sem FOR vale como ALL; use FOR SELECT (escrita só por função).`);
      else if (forClause[1].toLowerCase() !== 'select') {
        problems.push(`${at}: policy FOR ${forClause[1].toUpperCase()} é proibida; escrita só por função SECURITY DEFINER.`);
      }
    }

    if (/^grant\b/i.test(text)) {
      const onRoutine = /\bon\s+(?:all\s+)?(?:function|functions|routine|routines|procedure|procedures|schema)\b/i.test(text);
      if (/\bto\b[^;]*\banon\b/i.test(text)) problems.push(`${at}: GRANT para anon é proibido.`);
      if (!onRoutine && /\b(insert|update|delete|truncate|all)\b/i.test(text.split(/\bon\b/i)[0]) && /\bto\b[^;]*\b(authenticated|public)\b/i.test(text)) {
        problems.push(`${at}: privilégio de escrita em tabela para authenticated/PUBLIC é proibido.`);
      }
    }

    const fn = text.match(/^create\s+(?:or\s+replace\s+)?function\s+(?:(\w+)\.)?"?(\w+)"?\s*\(/i);
    if (fn) {
      const schema = (fn[1] ?? 'public').toLowerCase();
      const name = fn[2];
      const isTrigger = /\breturns\s+trigger\b/i.test(text);
      if (/\bsecurity\s+definer\b/i.test(text) && !/\bset\s+search_path\s*(?:=|to)\s*(?:''|"")/i.test(text)) {
        problems.push(`${at}: função ${schema}.${name} é SECURITY DEFINER sem SET search_path = ''.`);
      }
      const revoke = new RegExp(
        `revoke\\s+(?:all|execute)(?:\\s+privileges)?\\s+on\\s+function\\s+(?:${schema}\\.)?"?${name}"?\\b[^;]*\\bfrom\\b[^;]*\\bpublic\\b`,
        'i',
      );
      if (!isTrigger && !revoke.test(outside)) {
        problems.push(`${at}: função ${schema}.${name} sem REVOKE EXECUTE … FROM PUBLIC, anon (o padrão do Postgres é executável por todos).`);
      }
    }
  }

  // SQL dinâmica dentro dos corpos.
  for (const body of bodies) {
    for (const m of body.text.matchAll(/\bexecute\s+(?!format\s*\()([^;]*)/gi)) {
      if (m[1].includes('||')) {
        problems.push(`linha ${lineOf(sql, body.index + m.index)}: EXECUTE com concatenação (SQL injection); use format('%I', …) + EXECUTE … USING.`);
      }
    }
    for (const m of body.text.matchAll(/\bexecute\s+format\s*\(\s*'[^']*%s/gi)) {
      problems.push(`linha ${lineOf(sql, body.index + m.index)}: format() com %s em EXECUTE; use %I para identificadores e %L/USING para valores.`);
    }
  }

  return problems;
}

// --------------------------------------------------------- TypeScript ----

function checkSource(rel, text) {
  const problems = [];
  const lines = text.split('\n');
  const isRoute = /^src\/app\/api\/.+\/route\.tsx?$/.test(rel);

  lines.forEach((line, i) => {
    const at = `linha ${i + 1}`;
    const code = line.replace(/\/\/.*$/, '');
    if (/^\s*(\*|\/\*)/.test(line)) return;

    if (/SUPABASE_SECRET_KEY/.test(code) && !SECRET_KEY_ALLOWED.has(rel)) {
      problems.push(`${at}: SUPABASE_SECRET_KEY só pode ser lida em src/shared/db/admin-client.ts (e validada em env.ts).`);
    }
    if (/from\s+['"][^'"]*admin-client['"]/.test(code) && !ADMIN_CLIENT_IMPORTERS.some((re) => re.test(rel))) {
      problems.push(`${at}: o admin client (ignora RLS) só pode ser importado pelo rate limiter e por identity/infrastructure — nunca reexportado.`);
    }
    if (/\.(or|filter|textSearch)\(\s*`[^`]*\$\{/.test(code) || /\.(or|filter|textSearch)\([^)]*['"]\s*\+/.test(code)) {
      problems.push(`${at}: input interpolado em filtro PostgREST (.or/.filter/.textSearch) permite injeção; use .eq/.in/.ilike com valor ou uma RPC.`);
    }
    if (/auth\.getSession\s*\(/.test(code)) {
      problems.push(`${at}: auth.getSession() não valida o JWT no servidor; use o PrincipalResolver (getClaims/getUser + current_principal).`);
    }
    if (/\bconsole\.(log|info|debug|warn|error|trace)\s*\(/.test(code)) {
      problems.push(`${at}: console.* é proibido em src/; use o logger de @/shared/observability.`);
    }
    if (/dangerouslySetInnerHTML/.test(code)) {
      problems.push(`${at}: dangerouslySetInnerHTML é proibido.`);
    }
    if (/from\s+['"]next\/headers['"]/.test(code)) {
      problems.push(`${at}: não use next/headers; o pipeline lê NextRequest e escreve NextResponse (testável por invocação direta).`);
    }
    if (/NEXT_PUBLIC_SUPABASE/.test(code)) {
      problems.push(`${at}: variáveis do Supabase não usam prefixo público; o browser nunca fala com o Supabase (ADR 0002).`);
    }
    if (isRoute && /from\s+['"](@supabase\/|@\/shared\/db)/.test(code)) {
      problems.push(`${at}: route.ts não acessa o banco; delegue ao handler do módulo (ADR 0005).`);
    }
    if (isRoute && (/export\s+(async\s+)?function\b/.test(code) || /export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=/.test(code))) {
      problems.push(`${at}: route.ts só reexporta o handler (export { handler as POST } from '@/modules/...').`);
    }
  });

  return problems;
}

// ------------------------------------------------------------ Contrato ----

function checkContract(root, abs) {
  const redocly = path.join(root, 'node_modules', '.bin', 'redocly');
  if (!existsSync(redocly)) {
    const head = readFileSync(abs, 'utf8');
    if (head.includes('\t')) return ['o contrato contém TAB; YAML exige espaços.'];
    if (!/^openapi:\s*3\.1\./m.test(head)) return ['o contrato precisa declarar "openapi: 3.1.x".'];
    return [];
  }
  try {
    execFileSync(redocly, ['lint', abs, '--format=stylish'], {
      cwd: root,
      encoding: 'utf8',
      timeout: TOOL_TIMEOUT_MS,
      env: { ...process.env, REDOCLY_TELEMETRY: 'off', REDOCLY_SUPPRESS_UPDATE_NOTICE: 'true' },
    });
    return [];
  } catch (error) {
    const out = `${error.stdout ?? ''}${error.stderr ?? ''}`.slice(-MAX_OUTPUT_CHARS);
    return [`redocly lint falhou:\n${out}`];
  }
}

// ---------------------------------------------------------------- main ----

function formatWithPrettier(root, abs) {
  const prettier = path.join(root, 'node_modules', '.bin', 'prettier');
  if (!existsSync(prettier) || !PRETTIER_EXTENSIONS.has(path.extname(abs))) return;
  try {
    execFileSync(prettier, ['--write', '--log-level', 'warn', abs], { cwd: root, stdio: 'ignore', timeout: TOOL_TIMEOUT_MS });
  } catch {
    // formatação é conveniência; o CI cobra format:check
  }
}

try {
  const input = readHookInput();
  const root = projectDir(input);
  const rel = relativeToProject(root, input.tool_input?.file_path);
  if (!rel) process.exit(0);
  const abs = path.join(root, rel);
  if (!existsSync(abs)) process.exit(0);

  formatWithPrettier(root, abs);
  const text = readFileSync(abs, 'utf8');

  let problems = [];
  if (/^supabase\/migrations\/.+\.sql$/.test(rel)) problems = checkMigration(text);
  else if (/^src\/.+\.tsx?$/.test(rel) && !/\.test\.tsx?$/.test(rel)) problems = checkSource(rel, text);
  else if (/^contracts\/openapi[^/]*\.ya?ml$/.test(rel)) problems = checkContract(root, abs);

  if (problems.length > 0) {
    block(`[${HOOK}] ${rel} viola regras do projeto (AGENTS.md › Segurança/Banco):\n- ${problems.join('\n- ')}\nCorrija antes de seguir.`);
  }
  process.exit(0);
} catch (error) {
  failOpen(HOOK, error);
}
