// Testes da resolução de raiz do projeto (lib.mjs). Rodam com: node --test ".claude/hooks/*.test.mjs"
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, symlinkSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, it } from 'node:test';
import {
  describeGitError,
  existingMainRefs,
  gitFailureText,
  gitResult,
  gitToplevel,
  hasGitSegment,
  projectDir,
  relativeToProject,
  sameRepository,
} from './lib.mjs';
import { createFixture, git, installFakeGit, write } from './test-fixture.mjs';

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

/** Cria um repositório git próprio (aninhado/estranho) em `dir`. */
function initForeignRepo(dir) {
  mkdirSync(dir, { recursive: true });
  git(dir, 'init', '--quiet');
}

describe('projectDir: repositório git aninhado não sequestra a raiz (M4)', () => {
  for (const nested of [false, true]) {
    describe(nested ? 'worktree aninhada em <repo>/.claude/worktrees' : 'worktree em outro caminho', () => {
      let fx;
      beforeEach(() => {
        fx = createFixture({ nested });
      });
      afterEach(() => fx.cleanup());

      it('git init em <repo>/src: o arquivo de src/ resolve a raiz do repositório, com caminho relativo src/…', () => {
        initForeignRepo(path.join(fx.main, 'src'));
        const file = path.join(fx.main, 'src', 'x.ts');
        const root = withProjectDirEnv(fx.main, () => projectDir({ cwd: fx.main }, file));
        assert.equal(root, realpathSync(fx.main));
        assert.equal(relativeToProject(root, file), 'src/x.ts');
      });

      it('git init em <worktree>/src: a raiz continua sendo a da worktree (não cai no checkout principal)', () => {
        initForeignRepo(path.join(fx.worktree, 'src'));
        const file = path.join(fx.worktree, 'src', 'x.ts');
        const root = withProjectDirEnv(fx.main, () => projectDir({ cwd: fx.main }, file));
        assert.equal(root, fx.realWorktree);
        assert.equal(relativeToProject(root, file), 'src/x.ts');
      });

      it('git init em <repo>/supabase/migrations: a migration continua sob supabase/migrations/', () => {
        initForeignRepo(path.join(fx.main, 'supabase', 'migrations'));
        const file = path.join(fx.main, fx.initialMigration);
        const root = withProjectDirEnv(fx.main, () => projectDir({ cwd: fx.main }, file));
        assert.equal(relativeToProject(root, file), fx.initialMigration);
      });

      it('Stop/SessionStart (sem arquivo) com cwd num repositório aninhado: usa a raiz do repositório', () => {
        initForeignRepo(path.join(fx.main, 'src'));
        const root = withProjectDirEnv(fx.main, () => projectDir({ cwd: path.join(fx.main, 'src') }));
        assert.equal(root, realpathSync(fx.main));
      });
    });
  }

  describe('sem CLAUDE_PROJECT_DIR (comportamento atual preservado)', () => {
    let fx;
    beforeEach(() => {
      fx = createFixture();
    });
    afterEach(() => fx.cleanup());

    it('vale a raiz git mais próxima, inclusive a do repositório aninhado', () => {
      const nestedRepo = path.join(fx.main, 'src');
      initForeignRepo(nestedRepo);
      const file = path.join(nestedRepo, 'x.ts');
      const root = withProjectDirEnv(undefined, () => projectDir({ cwd: fx.main }, file));
      assert.equal(root, realpathSync(nestedRepo));
    });
  });

  describe('repositório sem relação com CLAUDE_PROJECT_DIR', () => {
    let fx;
    let foreign;
    beforeEach(() => {
      fx = createFixture();
      foreign = mkdtempSync(path.join(os.tmpdir(), 'hooks-foreign-'));
      git(foreign, 'init', '--quiet');
    });
    afterEach(() => {
      fx.cleanup();
      rmSync(foreign, { recursive: true, force: true });
    });

    it('arquivo de outro repositório cai em CLAUDE_PROJECT_DIR (e fica fora do projeto)', () => {
      const file = path.join(foreign, 'src', 'x.ts');
      const root = withProjectDirEnv(fx.main, () => projectDir({ cwd: foreign }, file));
      assert.equal(root, fx.main);
      assert.equal(relativeToProject(root, file), null);
    });
  });
});

describe('sameRepository', () => {
  let fx;
  let outside;
  beforeEach(() => {
    fx = createFixture();
    outside = mkdtempSync(path.join(os.tmpdir(), 'hooks-same-'));
  });
  afterEach(() => {
    fx.cleanup();
    rmSync(outside, { recursive: true, force: true });
  });

  it('checkout principal e worktree vinculada compartilham o repositório', () => {
    assert.equal(sameRepository(fx.main, fx.worktree), true);
    assert.equal(sameRepository(fx.worktree, path.join(fx.worktree, 'pasta', 'inexistente')), true);
  });

  it('repositório aninhado, repositório estranho e pasta fora de repositório não contam', () => {
    initForeignRepo(path.join(fx.main, 'src'));
    git(outside, 'init', '--quiet');
    assert.equal(sameRepository(path.join(fx.main, 'src'), fx.main), false);
    assert.equal(sameRepository(outside, fx.main), false);
    assert.equal(sameRepository(fx.main, path.join(os.tmpdir(), 'hooks-nao-existe-' + process.pid)), false);
  });
});

describe('hasGitSegment', () => {
  it('detecta segmento .git em qualquer posição, inclusive no fim e via ..', () => {
    assert.equal(hasGitSegment('/r/.git'), true);
    assert.equal(hasGitSegment('/r/.git/hooks/pre-commit'), true);
    assert.equal(hasGitSegment('/r/src/../.git/config'), true);
    assert.equal(hasGitSegment('/r/sub/.GIT/config'), true);
    assert.equal(hasGitSegment('/r/x\\.git\\config'), true); // separador do Windows
  });

  it('não confunde com nomes parecidos', () => {
    assert.equal(hasGitSegment('/r/.github/workflows/ci.yml'), false);
    assert.equal(hasGitSegment('/r/.gitignore'), false);
    assert.equal(hasGitSegment('/r/.gitattributes'), false);
    assert.equal(hasGitSegment('/r/foo.git/x'), false);
    assert.equal(hasGitSegment('/r/src/git/x.ts'), false);
  });
});

describe('falhas do git (describeGitError, gitResult, existingMainRefs)', () => {
  let fx;
  let outside;
  let previousPath;
  beforeEach(() => {
    fx = createFixture();
    outside = mkdtempSync(path.join(os.tmpdir(), 'hooks-gitfail-'));
    previousPath = process.env.PATH;
  });
  afterEach(() => {
    process.env.PATH = previousPath;
    fx.cleanup();
    rmSync(outside, { recursive: true, force: true });
  });

  it('classifica erros sintéticos: timeout, git ausente, não é repositório e demais falhas', () => {
    assert.equal(describeGitError({ code: 'ETIMEDOUT' }).kind, 'timeout');
    assert.equal(describeGitError({ killed: true, signal: 'SIGTERM' }).kind, 'timeout');
    assert.equal(describeGitError({ code: 'ENOENT' }).kind, 'unavailable');
    assert.equal(
      describeGitError({ status: 128, stderr: 'fatal: not a git repository (or any of the parent directories): .git\n' }).kind,
      'not-repo',
    );
    const other = describeGitError({ status: 128, stderr: 'fatal: index file corrupt' });
    assert.equal(other.kind, 'failed');
    assert.equal(other.status, 128);
    assert.equal(describeGitError(new Error('boom')).kind, 'failed');
  });

  it('fora de um repositório → not-repo', () => {
    const result = gitResult(outside, ['status', '--porcelain']);
    assert.equal(result.ok, false);
    assert.equal(result.kind, 'not-repo');
  });

  it('índice corrompido → failed (não é "não é um repositório")', () => {
    write(path.join(fx.main, '.git', 'index'), 'lixo');
    const result = gitResult(fx.main, ['status', '--porcelain']);
    assert.equal(result.ok, false);
    assert.equal(result.kind, 'failed');
    assert.equal(result.status, 128);
    assert.match(gitFailureText(result), /git falhou \(código 128\)/);
  });

  it('git que trava estoura o timeout → timeout', () => {
    const bin = mkdtempSync(path.join(os.tmpdir(), 'hooks-fakegit-'));
    try {
      process.env.PATH = installFakeGit(bin, [{ match: 'status', sleep: 10 }]);
      const result = gitResult(fx.main, ['status', '--porcelain'], { timeout: 300 });
      assert.equal(result.ok, false);
      assert.equal(result.kind, 'timeout');
      assert.equal(gitFailureText(result), 'git estourou o tempo limite');
    } finally {
      rmSync(bin, { recursive: true, force: true });
    }
  });

  it('HOOKS_GIT_TIMEOUT_MS só encurta o timeout (nunca alonga)', () => {
    const bin = mkdtempSync(path.join(os.tmpdir(), 'hooks-fakegit-'));
    const previousCap = process.env.HOOKS_GIT_TIMEOUT_MS;
    try {
      process.env.PATH = installFakeGit(bin, [{ match: 'status', sleep: 10 }]);
      process.env.HOOKS_GIT_TIMEOUT_MS = '300';
      assert.equal(gitResult(fx.main, ['status'], { timeout: 60000 }).kind, 'timeout');
    } finally {
      if (previousCap === undefined) delete process.env.HOOKS_GIT_TIMEOUT_MS;
      else process.env.HOOKS_GIT_TIMEOUT_MS = previousCap;
      rmSync(bin, { recursive: true, force: true });
    }
  });

  it('existingMainRefs lista as refs da main que existem, na ordem de preferência', () => {
    assert.deepEqual(existingMainRefs(fx.worktree), { ok: true, refs: ['refs/heads/main'] });
    const sha = git(fx.main, 'rev-parse', 'HEAD').trim();
    git(fx.main, 'update-ref', 'refs/remotes/origin/main', sha);
    assert.deepEqual(existingMainRefs(fx.worktree).refs, ['refs/heads/main', 'refs/remotes/origin/main']);
    git(fx.main, 'update-ref', '-d', 'refs/heads/main');
    assert.deepEqual(existingMainRefs(fx.worktree).refs, ['refs/remotes/origin/main']);
    git(fx.main, 'update-ref', '-d', 'refs/remotes/origin/main');
    assert.deepEqual(existingMainRefs(fx.worktree), { ok: true, refs: [] });
  });

  it('existingMainRefs devolve a falha do git quando ele não consegue responder', () => {
    const result = existingMainRefs(outside);
    assert.equal(result.ok, false);
    assert.equal(result.kind, 'not-repo');
  });
});
