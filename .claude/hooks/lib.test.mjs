// Testes da resolução de raiz do projeto (lib.mjs). Rodam com: node --test ".claude/hooks/*.test.mjs"
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import { gitToplevel, projectDir, relativeToProject } from './lib.mjs';
import { createFixture, write } from './test-fixture.mjs';

const MIGRATION = 'supabase/migrations/20260102000000_new.sql';

/** Executa `fn` com CLAUDE_PROJECT_DIR (ou sem ela, se undefined) e restaura o valor original. */
function withProjectDirEnv(value, fn) {
  const previous = process.env.CLAUDE_PROJECT_DIR;
  if (value === undefined) delete process.env.CLAUDE_PROJECT_DIR;
  else process.env.CLAUDE_PROJECT_DIR = value;
  try {
    return fn();
  } finally {
    if (previous === undefined) delete process.env.CLAUDE_PROJECT_DIR;
    else process.env.CLAUDE_PROJECT_DIR = previous;
  }
}

describe('projectDir: arquivo editado numa worktree com CLAUDE_PROJECT_DIR no checkout principal', () => {
  for (const nested of [false, true]) {
    describe(nested ? 'worktree aninhada em <repo>/.claude/worktrees' : 'worktree em outro caminho', () => {
      let fx;
      beforeEach(() => {
        fx = createFixture({ nested });
      });
      afterEach(() => fx.cleanup());

      it('resolve a raiz da worktree, não a do checkout principal', () => {
        const file = write(path.join(fx.worktree, MIGRATION), '-- x\n');
        const root = withProjectDirEnv(fx.main, () => projectDir({ cwd: fx.main }, file));
        assert.equal(root, fx.realWorktree);
        assert.equal(relativeToProject(root, file), MIGRATION);
      });

      it('resolve arquivo ainda inexistente em subpasta ainda inexistente', () => {
        const file = path.join(fx.worktree, 'src', 'modules', 'tracking', 'domain', 'new-file.ts');
        const root = withProjectDirEnv(fx.main, () => projectDir({ cwd: fx.main }, file));
        assert.equal(root, fx.realWorktree);
        assert.equal(relativeToProject(root, file), 'src/modules/tracking/domain/new-file.ts');
      });

      it('arquivo no checkout principal continua resolvendo o checkout principal', () => {
        const file = path.join(fx.main, MIGRATION);
        const root = withProjectDirEnv(fx.main, () => projectDir({ cwd: fx.worktree }, file));
        assert.equal(root, realpathSync(fx.main));
        assert.equal(relativeToProject(root, file), MIGRATION);
      });

      it('sem arquivo (Stop, SubagentStop, SessionStart), usa o cwd do evento', () => {
        const sub = path.join(fx.worktree, 'src');
        mkdirSync(sub, { recursive: true });
        assert.equal(
          withProjectDirEnv(fx.main, () => projectDir({ cwd: fx.worktree })),
          fx.realWorktree,
        );
        assert.equal(
          withProjectDirEnv(fx.main, () => projectDir({ cwd: sub })),
          fx.realWorktree,
        );
      });
    });
  }
});

describe('projectDir: fallbacks quando o git não resolve', () => {
  let outside;
  let fx;
  beforeEach(() => {
    fx = createFixture();
    outside = mkdtempSync(path.join(os.tmpdir(), 'hooks-outside-'));
  });
  afterEach(() => {
    fx.cleanup();
    rmSync(outside, { recursive: true, force: true });
  });

  it('arquivo fora de qualquer repositório → CLAUDE_PROJECT_DIR', () => {
    const file = path.join(outside, 'sub', 'a.ts');
    assert.equal(gitToplevel(outside), null, 'pré-condição: o tmp de teste não pode estar dentro de um repositório');
    const root = withProjectDirEnv(fx.main, () => projectDir({ cwd: outside }, file));
    assert.equal(root, fx.main);
    assert.equal(relativeToProject(root, file), null);
  });

  it('sem CLAUDE_PROJECT_DIR → cwd do evento; sem cwd → process.cwd()', () => {
    const file = path.join(outside, 'a.ts');
    assert.equal(
      withProjectDirEnv(undefined, () => projectDir({ cwd: outside }, file)),
      outside,
    );
    assert.equal(
      withProjectDirEnv(undefined, () => projectDir({}, path.join(outside, 'b.ts'))),
      process.cwd(),
    );
  });

  it('cwd do evento fora de repositório (sem arquivo) → CLAUDE_PROJECT_DIR', () => {
    assert.equal(
      withProjectDirEnv(fx.main, () => projectDir({ cwd: outside })),
      fx.main,
    );
  });
});

describe('gitToplevel', () => {
  let fx;
  beforeEach(() => {
    fx = createFixture();
  });
  afterEach(() => fx.cleanup());

  it('sobe até o ancestral existente mais próximo', () => {
    const missing = path.join(fx.worktree, 'a', 'b', 'c');
    assert.equal(gitToplevel(missing), fx.realWorktree);
  });

  it('devolve null dentro de .git (sem work tree)', () => {
    assert.equal(gitToplevel(path.join(fx.main, '.git')), null);
  });
});

describe('relativeToProject', () => {
  let fx;
  beforeEach(() => {
    fx = createFixture();
  });
  afterEach(() => fx.cleanup());

  it('devolve null para arquivo fora da raiz e para a própria raiz', () => {
    assert.equal(relativeToProject(fx.realWorktree, path.join(fx.main, MIGRATION)), null);
    assert.equal(relativeToProject(fx.realWorktree, fx.realWorktree), null);
    assert.equal(relativeToProject(fx.realWorktree, undefined), null);
  });

  it('aceita caminho relativo à raiz', () => {
    assert.equal(relativeToProject(fx.realWorktree, MIGRATION), MIGRATION);
  });

  it('reconhece arquivo acessado por um symlink para a worktree', (t) => {
    const link = path.join(fx.base, 'link-to-worktree');
    try {
      symlinkSync(fx.worktree, link, 'dir');
    } catch {
      t.skip('sem permissão para criar symlink neste ambiente');
      return;
    }
    const file = path.join(link, 'src', 'novo', 'a.ts');
    const root = withProjectDirEnv(fx.main, () => projectDir({ cwd: fx.main }, file));
    assert.equal(root, fx.realWorktree);
    assert.equal(relativeToProject(root, file), 'src/novo/a.ts');
  });
});
