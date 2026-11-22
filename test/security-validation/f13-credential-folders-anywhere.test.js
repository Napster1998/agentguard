// F13 (MEDIUM, FIXED): found in a live demo on Linux, not by unit tests. The
// shipped default denied "~/.ssh/**" and "~/.aws/**", which only match the
// folders directly under the HOME directory. A copy of a credentials folder
// anywhere else (a backup, Downloads, a project folder: /home/u/DemoFiles/.aws/
// credentials) was ALLOWED, and an agent could read it. The default now also
// denies any ".ssh"/".aws" folder at any depth. These tests load the SHIPPED
// policy so the data cannot regress, and also pin the boundary: only whole
// directory names match, so look-alike names stay allowed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import yaml from 'js-yaml';
import { fileURLToPath } from 'node:url';

import { PolicyEngine, applyDefaults } from '../../src/core/policy-engine.js';
import { createAction } from '../../src/core/action.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const ctx = { source: 'mcp', sessionId: 's1' };
const home = os.homedir();

const mustBlock = [
  path.join(home, '.aws', 'credentials'),
  path.join(home, '.ssh', 'id_rsa'),
  path.join(home, 'DemoFiles', '.aws', 'credentials'),
  path.join(home, 'DemoFiles', '.aws', 'config'),
  path.join(home, 'Downloads', 'backup', '.ssh', 'known_hosts'),
  '/srv/app/.aws/credentials',
  '/home/someone/else/.ssh/id_ed25519.pub',
  'C:\\Users\\someone\\old-laptop\\.aws\\credentials',
  'project/.aws/credentials',
  './.ssh/config',
  '~/DemoFiles/.aws/credentials',
  // case does not matter on Windows/macOS file systems
  '/home/x/.AWS/Credentials',
];
const mustNotBlock = [
  path.join(home, 'DemoFiles', 'notes.txt'),
  '/home/someone/project/src/index.js',
  '/home/someone/my.aws/credentials', // not a ".aws" folder
  '/home/someone/.awsome/credentials',
  '/home/someone/dotaws/credentials',
  '/home/someone/project/aws/credentials', // no leading dot
  '/home/someone/project/notes.ssh.txt',
  '/home/someone/.sshd-docs/readme.md',
];

function verdict(engine, value) {
  return engine.evaluate(createAction({ verb: 'read', resourceType: 'filesystem', resourceValue: value, context: ctx })).verdict;
}

for (const file of ['policy/default-policy.yaml']) {
  test(`F13 FIXED (${file}): a .ssh/.aws folder is BLOCKed anywhere; look-alike names are not`, () => {
    const engine = new PolicyEngine(applyDefaults(yaml.load(fs.readFileSync(path.join(root, file), 'utf8'))));
    for (const v of mustBlock) assert.equal(verdict(engine, v), 'BLOCK', `${v} should be BLOCK`);
    for (const v of mustNotBlock) assert.notEqual(verdict(engine, v), 'BLOCK', `${v} must not be BLOCK`);
  });
}

test('F13: the shipped default still reports the home-folder rule first, so documented example output is unchanged', () => {
  const policy = applyDefaults(yaml.load(fs.readFileSync(path.join(root, 'policy', 'default-policy.yaml'), 'utf8')));
  const engine = new PolicyEngine(policy);
  const d = engine.evaluate(createAction({ verb: 'read', resourceType: 'filesystem', resourceValue: '~/.aws/credentials', context: ctx }));
  assert.match(d.reason, /~\/\.aws\/\*\*/);
});
