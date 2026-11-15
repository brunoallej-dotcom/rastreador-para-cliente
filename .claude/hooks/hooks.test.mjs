// Testes ponta a ponta dos hooks: executa os scripts de verdade (JSON no stdin, como o Claude Code faz) com
// CLAUDE_PROJECT_DIR apontando para o checkout principal enquanto o trabalho acontece numa worktree.
// Rodam com: node --test ".claude/hooks/*.test.mjs"
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { createFixture, git, installFakePrettier, runHook, write } from './test-fixture.mjs';

const NEW_MIGRATION = 'supabase/migrations/20260102000000_new.sql';
const SQL_WITHOUT_RLS = 'CREATE TABLE public.clients (id uuid PRIMARY KEY);\n';
const SQL_WITH_RLS = `${SQL_WITHOUT_RLS}ALTER TABLE public.clients ENABLE ROW LEVEL SECURITY;\n`;

/** Exige saída vazia: um hook que não bloqueia não escreve nada. */
function assertSilent(result, expectedStatus = 0) {
  assert.equal(result.status, expectedStatus, `stdout=${result.stdout} stderr=${result.stderr}`);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, '');
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

      it('sem node_modules na worktree, segue sem formatar e sem erro', () => {
        const file = write(wt('src/shared/clean.ts'), 'export const A = 1;\n');
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
