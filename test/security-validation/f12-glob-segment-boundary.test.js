// F12 (MEDIUM, FIXED): found while verifying F11. glob-match turned `**` into
// `.*` and then CONSUMED the following `/`, so `**/.env.*` compiled to
// /^.*\.env\..*$/ - with no requirement that `.env` begin a path segment.
//   - deny/warn lists over-matched (my.env.txt, notcredentials.json): the
//     safe direction, but real false positives.
//   - allowlists using a leading `**/` FAILED OPEN: `**/src/**` also allowed
//     /etc/mysrc/evil, treating a path outside the allowlist as inside it.
// Fix: `**/` now means "zero or more WHOLE directory segments".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchesAny } from '../../src/core/glob-match.js';
import { PolicyEngine, applyDefaults } from '../../src/core/policy-engine.js';
import { createAction } from '../../src/core/action.js';

const hit = (value, pattern) => matchesAny(value, [pattern]) !== null;

test('F12a FIXED: `**/name` matches the name as a whole segment, at any depth, never as a suffix of another name', () => {
  for (const ok of ['id_ed25519', './id_ed25519', '/home/u/.ssh/id_ed25519', 'a/b/c/id_ed25519', 'C:\\Users\\u\\id_ed25519']) {
    assert.equal(hit(ok, '**/id_ed25519'), true, `${ok} should match`);
  }
  for (const no of ['/home/u/notid_ed25519', 'myid_ed25519', '/a/b/id_ed25519.pub', '/a/id_ed25519/x']) {
    assert.equal(hit(no, '**/id_ed25519'), false, `${no} should NOT match`);
  }
});

test('F12b FIXED: `**/.env.*` no longer matches names that merely contain ".env."', () => {
  assert.equal(hit('/p/.env.local', '**/.env.*'), true);
  assert.equal(hit('/p/my.env.txt', '**/.env.*'), false);
  assert.equal(hit('/p/notcredentials.json', '**/credentials.json'), false);
  assert.equal(hit('/p/credentials.json', '**/credentials.json'), true);
});

test('F12c FIXED: an allowlist with a leading `**/` no longer treats an outside path as inside it', () => {
  const engine = new PolicyEngine(applyDefaults({ filesystem: { allow: ['**/src/**'] } }));
  const verdict = (v) => engine.evaluate(createAction({ verb: 'read', resourceType: 'filesystem', resourceValue: v, context: { source: 'mcp', sessionId: 's' } })).verdict;
  assert.equal(verdict('/work/proj/src/index.js'), 'ALLOW');
  assert.equal(verdict('src/index.js'), 'ALLOW');
  assert.notEqual(verdict('/etc/mysrc/evil'), 'ALLOW', 'mysrc is not the segment "src"');
});

test('F12d no regression: `**` in the middle and at the end behave as before', () => {
  assert.equal(hit('a/b', 'a/**/b'), true, 'zero segments');
  assert.equal(hit('a/x/b', 'a/**/b'), true);
  assert.equal(hit('a/x/y/b', 'a/**/b'), true);
  assert.equal(hit('a/xb', 'a/**/b'), false);
  assert.equal(hit('~/.ssh/id_rsa', '~/.ssh/**'), true);
  assert.equal(hit('~/.ssh/deep/er/key', '~/.ssh/**'), true);
  assert.equal(hit('/p/key.pem', '**/*.pem'), true);
  assert.equal(hit('/p/key.pem.bak', '**/*.pem'), false);
});
