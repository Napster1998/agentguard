// F4 (HIGH, FIXED): glob-match.js now lexically collapses `.`/`..` segments
// before matching (see collapseDotSegments in glob-match.js). This is
// still NOT full canonicalization (no symlink resolution, no filesystem
// access) - see README "Limitations" - but it closes the traversal bypass
// in both directions: escaping an allowlist, and evading a denylist.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PolicyEngine, applyDefaults } from '../../src/core/policy-engine.js';
import { createAction } from '../../src/core/action.js';

const ctx = { source: 'mcp', sessionId: 's1' };
function fsAction(value) {
  return createAction({ verb: 'read', resourceType: 'filesystem', resourceValue: value, context: ctx });
}

test('F4a baseline: a value inside an allowlisted directory is ALLOWED', () => {
  const policy = applyDefaults({ filesystem: { allow: ['./workspace/**'] } });
  const engine = new PolicyEngine(policy);
  const d = engine.evaluate(fsAction('./workspace/src/index.js'));
  assert.equal(d.verdict, 'ALLOW');
});

test('F4a FIXED: traversal out of an allowlisted directory is no longer treated as inside it', () => {
  const policy = applyDefaults({ filesystem: { allow: ['./workspace/**'] } });
  const engine = new PolicyEngine(policy);
  const escaping = './workspace/../../../etc/passwd';
  const d = engine.evaluate(fsAction(escaping));
  assert.notEqual(d.verdict, 'ALLOW', 'the collapsed path ("../../etc/passwd") no longer lexically matches the workspace prefix');
});

test('F4b baseline: a directly-denied path is blocked', () => {
  const policy = applyDefaults({ filesystem: { deny: ['~/.ssh/**'] } });
  const engine = new PolicyEngine(policy);
  const d = engine.evaluate(fsAction('~/.ssh/id_rsa'));
  assert.equal(d.verdict, 'BLOCK');
});

test('F4b FIXED: traversal INTO a denied path is now caught by filesystem.deny', () => {
  const policy = applyDefaults({ filesystem: { deny: ['~/.ssh/**'] } });
  const engine = new PolicyEngine(policy);
  const escaping = '~/some-other-dir/../.ssh/id_rsa';
  const d = engine.evaluate(fsAction(escaping));
  assert.equal(d.verdict, 'BLOCK', 'the collapsed path ("~/.ssh/id_rsa") now matches filesystem.deny as intended');
  assert.equal(d.rule, 'filesystem.deny');
});

test('F4c: a deeply escaping relative path resolving to the real home ~/.ssh is still caught', () => {
  const policy = applyDefaults({ filesystem: { deny: ['~/.ssh/**'] } });
  const engine = new PolicyEngine(policy);
  const d = engine.evaluate(fsAction('./a/b/c/../../../../.ssh/id_rsa'.replace('./', '~/')));
  assert.equal(d.verdict, 'BLOCK');
});

test('F4d: an absolute traversal attempt is also collapsed correctly', () => {
  const policy = applyDefaults({ filesystem: { deny: ['/etc/shadow'] } });
  const engine = new PolicyEngine(policy);
  const d = engine.evaluate(fsAction('/var/www/../../etc/shadow'));
  assert.equal(d.verdict, 'BLOCK');
});
