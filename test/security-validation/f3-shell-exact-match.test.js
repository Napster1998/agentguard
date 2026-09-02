// F3 (HIGH, FIXED): shell.allowed/shell.deny now normalize to basename with
// common Windows executable extensions stripped before comparing, so a
// full path or an extension variant of a denied binary is caught the same
// as the bare name.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PolicyEngine, applyDefaults } from '../../src/core/policy-engine.js';
import { createAction } from '../../src/core/action.js';

const policy = applyDefaults({ shell: { allowed: [], deny: ['rm'] } });
const engine = new PolicyEngine(policy);
const ctx = { source: 'shell-exec', sessionId: 's1' };

function shellAction(binary) {
  return createAction({ verb: 'execute', resourceType: 'shell', resourceValue: binary, context: ctx });
}

test('F3 baseline: the bare denied binary is blocked by shell.deny', () => {
  const d = engine.evaluate(shellAction('rm'));
  assert.equal(d.verdict, 'BLOCK');
  assert.equal(d.rule, 'shell.deny');
});

test('F3 FIXED: a full POSIX path to the same binary is now caught by shell.deny', () => {
  const d = engine.evaluate(shellAction('/bin/rm'));
  assert.equal(d.verdict, 'BLOCK');
  assert.equal(d.rule, 'shell.deny');
});

test('F3 FIXED: a full Windows path with .exe is now caught by shell.deny', () => {
  const d = engine.evaluate(shellAction('C:\\Windows\\System32\\RM.EXE'));
  assert.equal(d.verdict, 'BLOCK');
  assert.equal(d.rule, 'shell.deny');
});

test('F3 FIXED: shell.deny now wins even when the same binary is also allowed under a different spelling', () => {
  const mixed = applyDefaults({ shell: { allowed: ['rm.exe'], deny: ['rm'] } });
  const d = new PolicyEngine(mixed).evaluate(shellAction('rm.exe'));
  assert.equal(d.verdict, 'BLOCK');
  assert.equal(d.rule, 'shell.deny');
});

test('F3 regression: legitimate allowed binaries still work exactly as before', () => {
  const p = applyDefaults({ shell: { allowed: ['git'], deny: [] } });
  const e = new PolicyEngine(p);
  assert.equal(e.evaluate(shellAction('git')).verdict, 'ALLOW');
  assert.equal(e.evaluate(shellAction('curl')).verdict, 'BLOCK');
});
