// Garante o registro dos hooks em .claude/settings.json. Roda com: node --test ".claude/hooks/*.test.mjs"
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, it } from 'node:test';
import { HOOKS_DIR, REPO_ROOT } from './test-fixture.mjs';

const settings = JSON.parse(readFileSync(path.join(REPO_ROOT, '.claude', 'settings.json'), 'utf8'));

function commandsFor(event) {
  return (settings.hooks?.[event] ?? []).flatMap((group) => group.hooks ?? []);
}

describe('.claude/settings.json', () => {
  it('registra stop-gates.mjs em Stop e em SubagentStop, com o mesmo comando e timeout', () => {
    const stop = commandsFor('Stop').filter((h) => h.command.includes('stop-gates.mjs'));
    const subagentStop = commandsFor('SubagentStop').filter((h) => h.command.includes('stop-gates.mjs'));
    assert.equal(stop.length, 1);
    assert.equal(subagentStop.length, 1);
    assert.deepEqual(subagentStop[0], stop[0]);
  });

  it('todo hook registrado aponta para um script que existe em .claude/hooks', () => {
    const events = Object.keys(settings.hooks ?? {});
    assert.ok(events.length > 0);
    for (const event of events) {
      for (const hook of commandsFor(event)) {
        const script = hook.command.match(/\.claude\/hooks\/([\w.-]+\.mjs)/)?.[1];
        assert.ok(script, `${event}: comando sem script de hook (${hook.command})`);
        assert.ok(existsSync(path.join(HOOKS_DIR, script)), `${event}: ${script} não existe`);
      }
    }
  });
});
