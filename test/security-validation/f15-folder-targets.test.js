// F15 (MEDIUM, FIXED): found during the Phase 6 (Antigravity hooks) feasibility
// review by evaluating folder paths against the shipped default policy. A
// pattern like "~/.aws/**" compiles to "<home>/.aws/" followed by anything, so
// it matched every path INSIDE the folder but not the folder itself:
// "<home>/.aws" and "<home>/.aws/" were ALLOWED. A tool that takes a folder
// (the MCP filesystem server's list_directory / directory_tree / search_files,
// or a grep-style search that returns file contents) could list or search a
// denied credentials folder without a single policy hit.
// Fix (src/core/glob-match.js): a pattern "X/**" also covers the folder X
// itself. Only whole folder names match, so look-alike names stay allowed.
// Residual gap, pinned below: a search of a PARENT folder (e.g. a recursive
// search of the home directory) cannot be judged by path matching, because
// nothing in the request names the denied folder.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import yaml from 'js-yaml';
import { fileURLToPath } from 'node:url';

import { PolicyEngine, applyDefaults } from '../../src/core/policy-engine.js';
import { createAction } from '../../src/core/action.js';
import { combineDecisions } from '../../src/core/decision.js';
import { mcpRequestToActions } from '../../src/adapters/mcp/translate.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const shipped = new PolicyEngine(applyDefaults(yaml.load(fs.readFileSync(path.join(root, 'policy', 'default-policy.yaml'), 'utf8'))));
const ctx = { source: 'mcp', sessionId: 's1', serverName: 'filesystem' };
const home = os.homedir();

const verdict = (engine, value) =>
  engine.evaluate(createAction({ verb: 'read', resourceType: 'filesystem', resourceValue: value, context: ctx })).verdict;

test('F15 FIXED: a denied credentials folder itself is BLOCKed, not only the files inside it', () => {
  for (const v of [
    '~/.aws',
    '~/.aws/',
    '~/.ssh',
    path.join(home, '.aws'),
    path.join(home, '.ssh') + path.sep,
    '/srv/app/.aws',
    'C:\\Users\\someone\\backup\\.ssh',
    './.aws',
    path.join(home, '.kube'),
    path.join(home, '.config', 'gcloud'),
  ]) {
    assert.equal(verdict(shipped, v), 'BLOCK', `${v} should be BLOCK`);
  }
});

test('F15 FIXED: listing a denied folder through the MCP filesystem server is BLOCKed end to end', () => {
  for (const tool of ['list_directory', 'directory_tree', 'search_files']) {
    const actions = mcpRequestToActions(
      { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: tool, arguments: { path: path.join(home, '.aws') } } },
      ctx
    );
    const final = combineDecisions(actions.map((a) => shipped.evaluate(a)), { verdict: 'ALLOW' });
    assert.equal(final.verdict, 'BLOCK', `${tool} on ~/.aws`);
    assert.equal(final.rule, 'filesystem.deny');
  }
});

test('F15: only whole folder names match; look-alikes and ordinary folders stay allowed', () => {
  for (const v of ['~/.awsome', '/home/x/my.aws', '/home/x/project', '/home/x/project/', '/home/x/.sshd-docs', path.join(home, 'DemoFiles')]) {
    assert.notEqual(verdict(shipped, v), 'BLOCK', `${v} must not be BLOCK`);
  }
  // A file pattern does not start covering a folder of the same name.
  const pem = new PolicyEngine(applyDefaults({ filesystem: { deny: ['**/*.pem'] } }));
  assert.equal(verdict(pem, '/certs/server.pem'), 'BLOCK');
  assert.equal(verdict(pem, '/certs'), 'ALLOW');
});

test('F15: an allowlist folder pattern now also covers the folder itself, without widening to look-alike names', () => {
  const engine = new PolicyEngine(applyDefaults({ filesystem: { allow: ['./workspace/**'] } }));
  assert.equal(verdict(engine, './workspace'), 'ALLOW', 'the allowed folder itself is inside the allowlist');
  assert.equal(verdict(engine, './workspace/src/a.js'), 'ALLOW');
  assert.equal(verdict(engine, './workspace-evil'), 'WARN', 'a sibling with a longer name is still outside');
  assert.equal(verdict(engine, './workspace/../etc'), 'WARN', 'traversal out of it is still outside (F4)');
});

test('F15 RESIDUAL (stays open, by design): a search of a PARENT folder is not judged by path matching', () => {
  // Nothing in "search my home folder" names ~/.aws, so a lexical rule cannot
  // know the search will reach it. Documented in SECURITY-ASSESSMENT.md F15.
  assert.equal(verdict(shipped, home), 'ALLOW');
  assert.equal(verdict(shipped, '~'), 'ALLOW');
});
