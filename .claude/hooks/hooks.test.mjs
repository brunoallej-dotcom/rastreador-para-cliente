// Testes ponta a ponta dos hooks: executa os scripts de verdade (JSON no stdin, como o Claude Code faz) com
// CLAUDE_PROJECT_DIR apontando para o checkout principal enquanto o trabalho acontece numa worktree.
// Rodam com: node --test ".claude/hooks/*.test.mjs"
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { commitAll, createFixture, git, installFakeGit, installFakePrettier, runHook, write } from './test-fixture.mjs';

const NEW_MIGRATION = 'supabase/migrations/20260102000000_new.sql';
const SQL_WITHOUT_RLS = 'CREATE TABLE public.clients (id uuid PRIMARY KEY);\n';
const SQL_WITH_RLS = `${SQL_WITHOUT_RLS}ALTER TABLE public.clients ENABLE ROW LEVEL SECURITY;\n`;
const PGTAP_TEST = 'supabase/tests/clients.test.sql';
const PGTAP_SQL = 'SELECT plan(1);\nSELECT ok(true);\nSELECT * FROM finish();\n';
const CONTRACT_FILE = 'contracts/openapi.v1.yaml';
const ROUTE_FILE = 'src/app/api/v1/widgets/route.ts';
const ROUTE_TS = "export { handler as GET } from '@/modules/x';\n";
const NOTICE_RE = /prettier\/redocly ausentes em .+; rode pnpm install --frozen-lockfile/g;

/** Exige saída vazia: um hook que não bloqueia não escreve nada. */
function assertSilent(result, expectedStatus = 0) {
  assert.equal(result.status, expectedStatus, `stdout=${result.stdout} stderr=${result.stderr}`);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
}

/** Cria um repositório git próprio (aninhado) em `dir`. */
function initNestedRepo(dir) {
  mkdirSync(dir, { recursive: true });
  git(dir, 'init', '--quiet');
}

/**
 * Pasta temporária com um falso git (ver installFakeGit). `env` vai para runHook: o PATH com o falso git e um
 * teto de 400 ms nos timeouts do git (HOOKS_GIT_TIMEOUT_MS), para os testes de travamento não esperarem 3-5 s.
 */
function fakeGit(rules) {
  const bin = mkdtempSync(path.join(os.tmpdir(), 'hooks-fakegit-'));
  return {
    env: { PATH: installFakeGit(bin, rules), HOOKS_GIT_TIMEOUT_MS: '400' },
    cleanup: () => rmSync(bin, { recursive: true, force: true }),
  };
}

for (const nested of [false, true]) {
  describe(`hooks numa worktree ${nested ? 'aninhada em .claude/worktrees' : 'fora do repositório'}`, () => {
    let fx;
    beforeEach(() => {
      fx = createFixture({ nested });
    });
    afterEach(() => fx.cleanup());

    const wt = (rel) => path.join(fx.worktree, rel);
    const editEvent = (tool, file, extra = {}) => ({
      hook_event_name: 'PostToolUse',
      cwd: fx.main,
      tool_name: tool,
      tool_input: { file_path: file, ...extra },
    });

    describe('post-edit-checks', () => {
      it('migration sem RLS dentro da worktree → exit 2 com a mensagem de RLS', () => {
        const file = write(wt(NEW_MIGRATION), SQL_WITHOUT_RLS);
        const result = runHook('post-edit-checks.mjs', editEvent('Write', file, { content: SQL_WITHOUT_RLS }), {
          projectDir: fx.main,
        });
        assert.equal(result.status, 2, `stderr=${result.stderr}`);
        assert.match(result.stderr, /public\.clients sem ENABLE ROW LEVEL SECURITY/);
        assert.match(result.stderr, new RegExp(NEW_MIGRATION));
      });

      it('migration com RLS dentro da worktree → exit 0', () => {
        const file = write(wt(NEW_MIGRATION), SQL_WITH_RLS);
        assertSilent(runHook('post-edit-checks.mjs', editEvent('Write', file), { projectDir: fx.main }));
      });

      it('código em src/ da worktree também é checado (console.* → exit 2)', () => {
        const file = write(wt('src/shared/x.ts'), "console.log('oi');\n");
        const result = runHook('post-edit-checks.mjs', editEvent('Edit', file), { projectDir: fx.main });
        assert.equal(result.status, 2, `stderr=${result.stderr}`);
        assert.match(result.stderr, /console\.\* é proibido/);
      });

      it('arquivo fora de qualquer repositório é ignorado', () => {
        const file = write(path.join(fx.base, 'outside', 'src', 'a.ts'), "console.log('oi');\n");
        assertSilent(runHook('post-edit-checks.mjs', editEvent('Edit', file), { projectDir: fx.main }));
      });

      it('usa o prettier do node_modules da worktree, não o do checkout principal', () => {
        const markerWorktree = path.join(fx.base, 'prettier-worktree.log');
        const markerMain = path.join(fx.base, 'prettier-main.log');
        installFakePrettier(fx.worktree, markerWorktree);
        installFakePrettier(fx.main, markerMain);
        const file = write(wt('src/shared/clean.ts'), 'export const A = 1;\n');
        assertSilent(runHook('post-edit-checks.mjs', editEvent('Write', file), { projectDir: fx.main }));
        assert.ok(existsSync(markerWorktree), 'o prettier da worktree deveria ter sido chamado');
        assert.ok(!existsSync(markerMain), 'o prettier do checkout principal não deveria ser chamado');
      });

      it('sem node_modules na worktree, segue sem erro e avisa (uma vez) que prettier/redocly faltam (M6)', () => {
        const file = write(wt('src/shared/clean.ts'), 'export const A = 1;\n');
        const result = runHook('post-edit-checks.mjs', editEvent('Write', file), { projectDir: fx.main });
        assert.equal(result.status, 0, `stderr=${result.stderr}`);
        assert.equal(result.stdout, '');
        assert.equal(result.stderr.match(NOTICE_RE)?.length, 1, result.stderr);
        assert.ok(result.stderr.includes(fx.realWorktree), 'o aviso nomeia a raiz da worktree');
      });

      it('sem node_modules e com violação: bloqueia (exit 2) e o aviso aparece uma só vez', () => {
        const file = write(wt('src/shared/x.ts'), "console.log('oi');\n");
        const result = runHook('post-edit-checks.mjs', editEvent('Edit', file), { projectDir: fx.main });
        assert.equal(result.status, 2, `stderr=${result.stderr}`);
        assert.match(result.stderr, /console\.\* é proibido/);
        assert.equal(result.stderr.match(NOTICE_RE)?.length, 1, result.stderr);
      });

      it('sem node_modules, editar contrato avisa uma vez só (prettier e redocly juntos)', () => {
        const file = write(wt(CONTRACT_FILE), 'openapi: 3.1.0\ninfo:\n  title: x\n');
        const result = runHook('post-edit-checks.mjs', editEvent('Write', file), { projectDir: fx.main });
        assert.equal(result.status, 0, `stderr=${result.stderr}`);
        assert.equal(result.stderr.match(NOTICE_RE)?.length, 1, result.stderr);
      });

      it('com prettier mas sem redocly, editar o contrato ainda avisa', () => {
        installFakePrettier(fx.worktree, path.join(fx.base, 'prettier.log'));
        const file = write(wt(CONTRACT_FILE), 'openapi: 3.1.0\ninfo:\n  title: x\n');
        const result = runHook('post-edit-checks.mjs', editEvent('Write', file), { projectDir: fx.main });
        assert.equal(result.status, 0, `stderr=${result.stderr}`);
        assert.equal(result.stderr.match(NOTICE_RE)?.length, 1, result.stderr);
      });

      it('sem node_modules, arquivo que o prettier não formata (.sql) não gera aviso', () => {
        const file = write(wt(NEW_MIGRATION), SQL_WITH_RLS);
        assertSilent(runHook('post-edit-checks.mjs', editEvent('Write', file), { projectDir: fx.main }));
      });
    });

    describe('guard-writes', () => {
      it('bloqueia escrita de .env.local na worktree', () => {
        const result = runHook(
          'guard-writes.mjs',
          editEvent('Write', wt('.env.local'), { content: 'FOO=bar\n' }),
          { projectDir: fx.main },
        );
        assert.equal(result.status, 2, `stderr=${result.stderr}`);
        assert.match(result.stderr, /Bloqueado: ".env.local"/);
      });

      it('permite .env.example na worktree', () => {
        assertSilent(
          runHook('guard-writes.mjs', editEvent('Write', wt('.env.example'), { content: 'FOO=\n' }), {
            projectDir: fx.main,
          }),
        );
      });

      it('bloqueia a edição de migration que já existe na main', () => {
        const result = runHook(
          'guard-writes.mjs',
          editEvent('Edit', wt(fx.initialMigration), { old_string: 'items', new_string: 'things' }),
          { projectDir: fx.main },
        );
        assert.equal(result.status, 2, `stderr=${result.stderr}`);
        assert.match(result.stderr, /já está na main e migrations são imutáveis/);
        assert.ok(result.stderr.includes(fx.initialMigration));
      });

      it('permite migration nova (nem na main) em pasta que ainda não existe, e a já commitada só na branch', () => {
        // Nova, num caminho que ainda não existe na worktree (PreToolUse acontece antes do Write).
        const novel = wt('supabase/migrations/nested/20260103000000_novel.sql');
        assertSilent(
          runHook('guard-writes.mjs', editEvent('Write', novel, { content: SQL_WITH_RLS }), { projectDir: fx.main }),
        );
        // Commitada na branch da worktree, mas ausente da main: continua editável.
        const onBranch = write(wt(NEW_MIGRATION), SQL_WITH_RLS);
        git(fx.worktree, 'add', NEW_MIGRATION);
        git(fx.worktree, '-c', 'user.name=T', '-c', 'user.email=t@example.invalid', 'commit', '--quiet', '-m', 'wip');
        assertSilent(
          runHook('guard-writes.mjs', editEvent('Edit', onBranch, { old_string: 'a', new_string: 'b' }), {
            projectDir: fx.main,
          }),
        );
      });

      it('migration da main é bloqueada mesmo que o cwd do processo seja a worktree', () => {
        const result = runHook(
          'guard-writes.mjs',
          editEvent('Edit', wt(fx.initialMigration), { old_string: 'items', new_string: 'things' }),
          { projectDir: fx.main, cwd: fx.worktree },
        );
        assert.equal(result.status, 2, `stderr=${result.stderr}`);
      });
    });

    describe('guard-writes: metadados do git (.git)', () => {
      const writeEvent = (file) => editEvent('Write', file, { content: 'x\n' });

      it('bloqueia qualquer escrita em .git do checkout principal e da worktree', () => {
        const targets = [
          path.join(fx.main, '.git', 'hooks', 'pre-commit'),
          path.join(fx.main, '.git', 'config'),
          path.join(fx.main, '.git'),
          wt('.git'), // o "arquivo .git" da worktree (aponta para o diretório do git)
          wt('src/../.git'),
        ];
        for (const target of targets) {
          const result = runHook('guard-writes.mjs', writeEvent(target), { projectDir: fx.main });
          assert.equal(result.status, 2, `${target}: stderr=${result.stderr}`);
          assert.match(result.stderr, /metadados do git/, target);
        }
      });

      it('bloqueia .git aninhado, caminho relativo e NotebookEdit', () => {
        const nestedGit = runHook('guard-writes.mjs', writeEvent(wt('src/.git/config')), { projectDir: fx.main });
        assert.equal(nestedGit.status, 2, nestedGit.stderr);
        const relative = runHook(
          'guard-writes.mjs',
          { tool_name: 'Write', cwd: fx.main, tool_input: { file_path: '.git/config', content: 'x' } },
          { projectDir: fx.main },
        );
        assert.equal(relative.status, 2, relative.stderr);
        const notebook = runHook(
          'guard-writes.mjs',
          { tool_name: 'NotebookEdit', cwd: fx.main, tool_input: { notebook_path: wt('.git/n.ipynb'), new_source: 'x' } },
          { projectDir: fx.main },
        );
        assert.equal(notebook.status, 2, notebook.stderr);
      });

      it('bloqueia a escrita através de um symlink que aponta para .git', (t) => {
        const link = wt('src/link-to-git');
        mkdirSync(path.dirname(link), { recursive: true });
        try {
          symlinkSync(path.join(fx.main, '.git'), link, 'dir');
        } catch {
          t.skip('sem permissão para criar symlink neste ambiente');
          return;
        }
        const result = runHook('guard-writes.mjs', writeEvent(path.join(link, 'config')), { projectDir: fx.main });
        assert.equal(result.status, 2, result.stderr);
        assert.match(result.stderr, /metadados do git/);
      });

      it('não confunde com .github, .gitignore, .gitattributes e pastas terminadas em .git', () => {
        for (const rel of ['.github/workflows/ci.yml', '.gitignore', '.gitattributes', 'docs/foo.git/readme.md']) {
          assertSilent(runHook('guard-writes.mjs', writeEvent(wt(rel)), { projectDir: fx.main }));
        }
      });
    });

    describe('repositório git aninhado não desliga as checagens (M4)', () => {
      it('post-edit-checks: git init em <worktree>/src; console.* em src/x.ts ainda → exit 2', () => {
        initNestedRepo(wt('src'));
        const file = write(wt('src/x.ts'), "console.log('oi');\n");
        const result = runHook('post-edit-checks.mjs', editEvent('Edit', file), { projectDir: fx.main });
        assert.equal(result.status, 2, `stderr=${result.stderr}`);
        assert.match(result.stderr, /console\.\* é proibido/);
        assert.match(result.stderr, /src\/x\.ts viola/);
      });

      it('post-edit-checks: git init em <worktree>/supabase/migrations; migration sem RLS ainda → exit 2', () => {
        initNestedRepo(wt('supabase/migrations'));
        const file = write(wt(NEW_MIGRATION), SQL_WITHOUT_RLS);
        const result = runHook('post-edit-checks.mjs', editEvent('Write', file), { projectDir: fx.main });
        assert.equal(result.status, 2, `stderr=${result.stderr}`);
        assert.match(result.stderr, /sem ENABLE ROW LEVEL SECURITY/);
      });

      it('guard-writes: git init em <worktree>/supabase/migrations; migration da main continua imutável', () => {
        initNestedRepo(wt('supabase/migrations'));
        const result = runHook(
          'guard-writes.mjs',
          editEvent('Edit', wt(fx.initialMigration), { old_string: 'items', new_string: 'things' }),
          { projectDir: fx.main },
        );
        assert.equal(result.status, 2, `stderr=${result.stderr}`);
        assert.match(result.stderr, /já está na main e migrations são imutáveis/);
      });

      it('guard-writes: git init em <repo>/supabase/migrations (checkout principal); migration da main continua imutável', () => {
        initNestedRepo(path.join(fx.main, 'supabase', 'migrations'));
        const result = runHook(
          'guard-writes.mjs',
          editEvent('Edit', path.join(fx.main, fx.initialMigration), { old_string: 'items', new_string: 'things' }),
          { projectDir: fx.main },
        );
        assert.equal(result.status, 2, `stderr=${result.stderr}`);
        assert.match(result.stderr, /já está na main e migrations são imutáveis/);
      });
    });

    for (const eventName of ['Stop', 'SubagentStop']) {
      describe(`stop-gates (${eventName})`, () => {
        const stopEvent = (extra = {}) => ({ hook_event_name: eventName, cwd: fx.worktree, ...extra });

        it('cwd na worktree com migration sem teste pgTAP → decision block', () => {
          write(wt(NEW_MIGRATION), SQL_WITH_RLS);
          const result = runHook('stop-gates.mjs', stopEvent(), { projectDir: fx.main, cwd: fx.main });
          assert.equal(result.status, 0, `stderr=${result.stderr}`);
          const output = JSON.parse(result.stdout);
          assert.equal(output.decision, 'block');
          assert.match(output.reason, /\[stop-gates\]/);
          assert.ok(output.reason.includes(NEW_MIGRATION), output.reason);
        });

        it('migration acompanhada de teste pgTAP → sem bloqueio', () => {
          write(wt(NEW_MIGRATION), SQL_WITH_RLS);
          write(wt('supabase/tests/clients.test.sql'), 'SELECT plan(1);\nSELECT ok(true);\nSELECT * FROM finish();\n');
          assertSilent(runHook('stop-gates.mjs', stopEvent(), { projectDir: fx.main, cwd: fx.main }));
        });

        it('a pendência da worktree não vaza para o checkout principal (e vice-versa)', () => {
          write(wt(NEW_MIGRATION), SQL_WITH_RLS);
          assertSilent(runHook('stop-gates.mjs', stopEvent({ cwd: fx.main }), { projectDir: fx.main }));
        });

        it('route.ts novo fora do contrato na worktree → decision block', () => {
          write(wt('src/app/api/v1/widgets/route.ts'), "export { handler as GET } from '@/modules/x';\n");
          const result = runHook('stop-gates.mjs', stopEvent(), { projectDir: fx.main, cwd: fx.main });
          assert.equal(result.status, 0, `stderr=${result.stderr}`);
          assert.equal(JSON.parse(result.stdout).decision, 'block');
        });

        it('stop_hook_active: true → exit 0 em silêncio, mesmo com pendência', () => {
          write(wt(NEW_MIGRATION), SQL_WITH_RLS);
          assertSilent(runHook('stop-gates.mjs', stopEvent({ stop_hook_active: true }), { projectDir: fx.main }));
        });

        it('M5: migration commitada sem teste pgTAP → decision block', () => {
          write(wt(NEW_MIGRATION), SQL_WITH_RLS);
          commitAll(fx.worktree, 'feat: migration sem teste');
          const result = runHook('stop-gates.mjs', stopEvent(), { projectDir: fx.main, cwd: fx.main });
          assert.equal(result.status, 0, `stderr=${result.stderr}`);
          assert.equal(result.stderr, '');
          const output = JSON.parse(result.stdout);
          assert.equal(output.decision, 'block');
          assert.ok(output.reason.includes(NEW_MIGRATION), output.reason);
        });

        it('M5: migration commitada junto com o teste pgTAP no mesmo commit → sem bloqueio', () => {
          write(wt(NEW_MIGRATION), SQL_WITH_RLS);
          write(wt(PGTAP_TEST), PGTAP_SQL);
          commitAll(fx.worktree, 'feat: migration com teste');
          assertSilent(runHook('stop-gates.mjs', stopEvent(), { projectDir: fx.main, cwd: fx.main }));
        });

        it('M5: migration e teste em commits diferentes da branch → sem bloqueio (união da branch)', () => {
          write(wt(NEW_MIGRATION), SQL_WITH_RLS);
          commitAll(fx.worktree, 'feat: migration');
          write(wt(PGTAP_TEST), PGTAP_SQL);
          commitAll(fx.worktree, 'test: pgTAP');
          assertSilent(runHook('stop-gates.mjs', stopEvent(), { projectDir: fx.main, cwd: fx.main }));
        });

        it('M5: migration commitada + teste ainda não commitado → sem bloqueio (união com a árvore)', () => {
          write(wt(NEW_MIGRATION), SQL_WITH_RLS);
          commitAll(fx.worktree, 'feat: migration');
          write(wt(PGTAP_TEST), PGTAP_SQL);
          assertSilent(runHook('stop-gates.mjs', stopEvent(), { projectDir: fx.main, cwd: fx.main }));
        });

        it('M5: migration commitada e depois apagada na árvore → sem bloqueio', () => {
          const file = write(wt(NEW_MIGRATION), SQL_WITH_RLS);
          commitAll(fx.worktree, 'feat: migration');
          rmSync(file);
          assertSilent(runHook('stop-gates.mjs', stopEvent(), { projectDir: fx.main, cwd: fx.main }));
        });

        it('M5: migration da main alterada num commit da branch, sem teste → decision block', () => {
          write(wt(fx.initialMigration), `${SQL_WITH_RLS}-- ajuste\n`);
          commitAll(fx.worktree, 'fix: migration');
          const result = runHook('stop-gates.mjs', stopEvent(), { projectDir: fx.main, cwd: fx.main });
          assert.equal(JSON.parse(result.stdout).decision, 'block');
        });

        it('M5: route.ts commitado fora do contrato → decision block', () => {
          write(wt(ROUTE_FILE), ROUTE_TS);
          commitAll(fx.worktree, 'feat: rota');
          const result = runHook('stop-gates.mjs', stopEvent(), { projectDir: fx.main, cwd: fx.main });
          assert.equal(result.status, 0, `stderr=${result.stderr}`);
          const output = JSON.parse(result.stdout);
          assert.equal(output.decision, 'block');
          assert.match(output.reason, /\/widgets/);
        });

        it('M5: route.ts commitado com o path no contrato (mesmo commit) → sem bloqueio', () => {
          write(wt(CONTRACT_FILE), 'openapi: 3.1.0\npaths:\n  /widgets:\n    get: {}\n');
          write(wt(ROUTE_FILE), ROUTE_TS);
          commitAll(fx.worktree, 'feat: rota com contrato');
          assertSilent(runHook('stop-gates.mjs', stopEvent(), { projectDir: fx.main, cwd: fx.main }));
        });

        it('M5: route.ts commitado, path adicionado ao contrato só na árvore → sem bloqueio', () => {
          write(wt(ROUTE_FILE), ROUTE_TS);
          commitAll(fx.worktree, 'feat: rota');
          write(wt(CONTRACT_FILE), 'openapi: 3.1.0\npaths:\n  /widgets:\n    get: {}\n');
          assertSilent(runHook('stop-gates.mjs', stopEvent(), { projectDir: fx.main, cwd: fx.main }));
        });

        it('M5: route.ts commitado e depois editado na árvore continua contando como novo → decision block', () => {
          write(wt(ROUTE_FILE), ROUTE_TS);
          commitAll(fx.worktree, 'feat: rota');
          write(wt(ROUTE_FILE), `${ROUTE_TS}// editado\n`);
          const result = runHook('stop-gates.mjs', stopEvent(), { projectDir: fx.main, cwd: fx.main });
          assert.equal(JSON.parse(result.stdout).decision, 'block');
        });

        it('stop_hook_active: true → silêncio mesmo com migration commitada sem teste', () => {
          write(wt(NEW_MIGRATION), SQL_WITH_RLS);
          commitAll(fx.worktree, 'feat: migration sem teste');
          assertSilent(runHook('stop-gates.mjs', stopEvent({ stop_hook_active: true }), { projectDir: fx.main, cwd: fx.main }));
        });

        it('árvore limpa → sem bloqueio', () => {
          assertSilent(runHook('stop-gates.mjs', stopEvent(), { projectDir: fx.main, cwd: fx.main }));
        });
      });
    }

    describe('session-context', () => {
      it('lê o NOTES.md da worktree do cwd do evento, não o do checkout principal', () => {
        write(wt('NOTES.md'), '# Notes\n\n## Status atual\n\n- status-da-worktree\n\n## Log\n');
        const result = runHook('session-context.mjs', { hook_event_name: 'SessionStart', cwd: fx.worktree }, {
          projectDir: fx.main,
        });
        assert.equal(result.status, 0, `stderr=${result.stderr}`);
        assert.match(result.stdout, /status-da-worktree/);
        assert.doesNotMatch(result.stdout, /status-da-main/);
      });

      it('no checkout principal, lê o NOTES.md da main', () => {
        const result = runHook('session-context.mjs', { hook_event_name: 'SessionStart', cwd: fx.main }, {
          projectDir: fx.main,
        });
        assert.equal(result.status, 0, `stderr=${result.stderr}`);
        assert.match(result.stdout, /status-da-main/);
      });
    });
  });
}

describe('hooks no checkout principal (sem worktree)', () => {
  let fx;
  beforeEach(() => {
    fx = createFixture();
  });
  afterEach(() => fx.cleanup());

  it('post-edit-checks: migration sem RLS → exit 2', () => {
    const file = write(path.join(fx.main, NEW_MIGRATION), SQL_WITHOUT_RLS);
    const result = runHook(
      'post-edit-checks.mjs',
      { tool_name: 'Write', cwd: fx.main, tool_input: { file_path: file } },
      { projectDir: fx.main },
    );
    assert.equal(result.status, 2, `stderr=${result.stderr}`);
    assert.match(result.stderr, /sem ENABLE ROW LEVEL SECURITY/);
  });

  it('guard-writes: bloqueia migration da main e .env.local; permite arquivo comum', () => {
    const base = { tool_name: 'Edit', cwd: fx.main };
    const migration = runHook(
      'guard-writes.mjs',
      { ...base, tool_input: { file_path: path.join(fx.main, fx.initialMigration), new_string: 'x' } },
      { projectDir: fx.main },
    );
    assert.equal(migration.status, 2, migration.stderr);
    const env = runHook(
      'guard-writes.mjs',
      { ...base, tool_input: { file_path: path.join(fx.main, '.env.local'), new_string: 'A=b' } },
      { projectDir: fx.main },
    );
    assert.equal(env.status, 2, env.stderr);
    assertSilent(
      runHook(
        'guard-writes.mjs',
        { ...base, tool_input: { file_path: path.join(fx.main, 'src', 'a.ts'), new_string: 'export const A = 1;' } },
        { projectDir: fx.main },
      ),
    );
  });

  it('stop-gates: migration sem teste → block; stop_hook_active → silêncio', () => {
    write(path.join(fx.main, NEW_MIGRATION), SQL_WITH_RLS);
    const result = runHook('stop-gates.mjs', { hook_event_name: 'Stop', cwd: fx.main }, { projectDir: fx.main });
    assert.equal(JSON.parse(result.stdout).decision, 'block');
    assertSilent(
      runHook('stop-gates.mjs', { hook_event_name: 'Stop', cwd: fx.main, stop_hook_active: true }, { projectDir: fx.main }),
    );
  });
});

describe('falha aberta', () => {
  let fx;
  beforeEach(() => {
    fx = createFixture();
  });
  afterEach(() => fx.cleanup());

  it('JSON inválido no stdin → exit 1 (avisa, não bloqueia) nos hooks de escrita', () => {
    for (const script of ['guard-writes.mjs', 'post-edit-checks.mjs']) {
      const result = runHook(script, null, { projectDir: fx.main, rawInput: '{not json' });
      assert.equal(result.status, 1, script);
      assert.match(result.stderr, /erro interno ignorado/);
    }
  });

  it('JSON inválido no stdin → stop-gates e session-context saem com 0', () => {
    for (const script of ['stop-gates.mjs', 'session-context.mjs']) {
      const result = runHook(script, null, { projectDir: fx.main, rawInput: '{not json' });
      assert.equal(result.status, 0, script);
    }
  });
});

describe('stop-gates: qual é a "main" da comparação (M5)', () => {
  let fx;
  beforeEach(() => {
    fx = createFixture();
  });
  afterEach(() => fx.cleanup());

  const stop = (cwd, extra = {}) =>
    runHook('stop-gates.mjs', { hook_event_name: 'Stop', cwd, ...extra }, { projectDir: fx.main, cwd: fx.main });
  const commitUntestedMigration = () => {
    write(path.join(fx.worktree, NEW_MIGRATION), SQL_WITH_RLS);
    commitAll(fx.worktree, 'feat: migration sem teste');
  };

  it('sem a main local, usa origin/main como base', () => {
    const sha = git(fx.main, 'rev-parse', 'HEAD').trim();
    git(fx.main, 'update-ref', 'refs/remotes/origin/main', sha);
    git(fx.main, 'update-ref', '-d', 'refs/heads/main');
    commitUntestedMigration();
    const result = stop(fx.worktree);
    assert.equal(result.status, 0, `stderr=${result.stderr}`);
    assert.equal(JSON.parse(result.stdout).decision, 'block');
  });

  it('sem main nem origin/main, só a árvore conta: commit passa, pendência não commitada bloqueia', () => {
    git(fx.main, 'update-ref', '-d', 'refs/heads/main');
    commitUntestedMigration();
    assertSilent(stop(fx.worktree));
    write(path.join(fx.worktree, 'supabase/migrations/20260103000000_other.sql'), SQL_WITH_RLS);
    assert.equal(JSON.parse(stop(fx.worktree).stdout).decision, 'block');
  });

  it('checkout principal na main com árvore limpa → nenhuma saída (com e sem origin/main)', () => {
    assertSilent(stop(fx.main));
    git(fx.main, 'update-ref', 'refs/remotes/origin/main', git(fx.main, 'rev-parse', 'HEAD').trim());
    assertSilent(stop(fx.main));
  });

  it('branch sem commits novos e árvore limpa → nenhuma saída', () => {
    assertSilent(stop(fx.worktree));
  });

  it('só a main local avançou depois que a branch saiu: o merge-base evita falso positivo', () => {
    write(path.join(fx.main, NEW_MIGRATION), SQL_WITH_RLS);
    commitAll(fx.main, 'feat: migration mergeada na main');
    assertSilent(stop(fx.worktree));
  });

  it('cwd fora de um repositório git e CLAUDE_PROJECT_DIR idem → exit 0 em silêncio', () => {
    const outside = mkdtempSync(path.join(os.tmpdir(), 'hooks-norepo-'));
    try {
      const result = runHook('stop-gates.mjs', { hook_event_name: 'Stop', cwd: outside }, { projectDir: outside });
      assertSilent(result);
    } finally {
      rmSync(outside, { recursive: true, force: true });
    }
  });
});

describe('stop-gates: falhas do git não viram "passou" silencioso (M5)', () => {
  let fx;
  beforeEach(() => {
    fx = createFixture();
  });
  afterEach(() => fx.cleanup());

  const stop = (extraEnv = {}) =>
    runHook('stop-gates.mjs', { hook_event_name: 'Stop', cwd: fx.main }, { projectDir: fx.main, env: extraEnv });

  it('índice corrompido (falha que não é "não é repositório") → aviso no stderr, exit 1, sem bloqueio', () => {
    write(path.join(fx.main, '.git', 'index'), 'lixo');
    const result = stop();
    assert.equal(result.status, 1, `stdout=${result.stdout} stderr=${result.stderr}`);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /\[stop-gates\] aviso: checagem não executada em .+ \(git falhou \(código 128\)\)/);
  });

  it('git que trava no status (timeout) → aviso de timeout, exit 1', () => {
    const fake = fakeGit([{ match: 'status', sleep: 10 }]);
    try {
      const result = stop(fake.env);
      assert.equal(result.status, 1, `stdout=${result.stdout} stderr=${result.stderr}`);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /checagem não executada .*git estourou o tempo limite/);
    } finally {
      fake.cleanup();
    }
  });

  it('falha só na parte da branch com árvore limpa → aviso no stderr, exit 1', () => {
    const fake = fakeGit([{ match: 'merge-base', exit: 128, stderr: 'fatal: boom' }]);
    try {
      const result = stop(fake.env);
      assert.equal(result.status, 1, `stdout=${result.stdout} stderr=${result.stderr}`);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /aviso: commits da branch não checados \(merge-base com refs\/heads\/main falhou/);
    } finally {
      fake.cleanup();
    }
  });

  it('falha na parte da branch, mas a árvore já tem pendência → bloqueia (exit 0 + JSON) e avisa', () => {
    write(path.join(fx.main, NEW_MIGRATION), SQL_WITH_RLS);
    const fake = fakeGit([{ match: 'diff', exit: 128, stderr: 'fatal: boom' }]);
    try {
      const result = stop(fake.env);
      assert.equal(result.status, 0, `stderr=${result.stderr}`);
      assert.equal(JSON.parse(result.stdout).decision, 'block');
      assert.match(result.stderr, /commits da branch não checados \(diff da branch falhou/);
    } finally {
      fake.cleanup();
    }
  });

  it('timeout na parte da branch → aviso de timeout', () => {
    const fake = fakeGit([{ match: 'merge-base', sleep: 10 }]);
    try {
      const result = stop(fake.env);
      assert.equal(result.status, 1, `stdout=${result.stdout} stderr=${result.stderr}`);
      assert.match(result.stderr, /merge-base com refs\/heads\/main falhou \(git estourou o tempo limite\)/);
    } finally {
      fake.cleanup();
    }
  });
});

describe('guard-writes: checagem "já está na main" falha fechada (M5)', () => {
  let fx;
  beforeEach(() => {
    fx = createFixture();
  });
  afterEach(() => fx.cleanup());

  const edit = (file, extraEnv = {}) =>
    runHook(
      'guard-writes.mjs',
      { tool_name: 'Edit', cwd: fx.main, tool_input: { file_path: file, old_string: 'items', new_string: 'things' } },
      { projectDir: fx.main, env: extraEnv },
    );
  const initial = () => path.join(fx.worktree, fx.initialMigration);
  const brandNew = () => path.join(fx.worktree, NEW_MIGRATION);

  it('git falhando ao ler a árvore da main → bloqueia, dizendo que a checagem não pôde rodar', () => {
    const fake = fakeGit([{ match: 'ls-tree', exit: 128, stderr: 'fatal: unable to read tree' }]);
    try {
      for (const file of [initial(), brandNew()]) {
        const result = edit(file, fake.env);
        assert.equal(result.status, 2, `${file}: stderr=${result.stderr}`);
        assert.match(result.stderr, /não foi possível verificar se supabase\/migrations\/.+ já está na main \(git falhou \(código 128\)\)/);
        assert.doesNotMatch(result.stderr, /migrations são imutáveis/);
      }
    } finally {
      fake.cleanup();
    }
  });

  it('git falhando ao listar as refs da main → bloqueia', () => {
    const fake = fakeGit([{ match: 'for-each-ref', exit: 128, stderr: 'fatal: boom' }]);
    try {
      const result = edit(brandNew(), fake.env);
      assert.equal(result.status, 2, `stderr=${result.stderr}`);
      assert.match(result.stderr, /não foi possível verificar/);
    } finally {
      fake.cleanup();
    }
  });

  it('git que trava (timeout) → bloqueia, citando o tempo limite', () => {
    const fake = fakeGit([{ match: 'ls-tree', sleep: 10 }]);
    try {
      const result = edit(initial(), fake.env);
      assert.equal(result.status, 2, `stderr=${result.stderr}`);
      assert.match(result.stderr, /não foi possível verificar .*git estourou o tempo limite/);
    } finally {
      fake.cleanup();
    }
  });

  it('a checagem só roda para migrations: arquivo comum passa mesmo com o ls-tree quebrado', () => {
    const fake = fakeGit([{ match: 'ls-tree', exit: 128 }]);
    try {
      assertSilent(edit(path.join(fx.worktree, 'src', 'a.ts'), fake.env));
    } finally {
      fake.cleanup();
    }
  });

  it('só origin/main (sem main local): migration que está nela continua imutável', () => {
    git(fx.main, 'update-ref', 'refs/remotes/origin/main', git(fx.main, 'rev-parse', 'HEAD').trim());
    git(fx.main, 'update-ref', '-d', 'refs/heads/main');
    const result = edit(initial());
    assert.equal(result.status, 2, `stderr=${result.stderr}`);
    assert.match(result.stderr, /já está na main e migrations são imutáveis/);
    assertSilent(edit(brandNew()));
  });

  it('sem nenhuma ref da main (repositório novo) → nada está "na main": libera', () => {
    git(fx.main, 'update-ref', '-d', 'refs/heads/main');
    assertSilent(edit(initial()));
  });
});
