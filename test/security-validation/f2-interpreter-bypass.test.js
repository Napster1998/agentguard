// F2 (CRITICAL, FIXED): shell.allowed only ever inspected the top-level
// binary. Node/Python (both in the SHIPPED DEFAULT policy's shell.allowed)
// are general-purpose interpreters — an inline-eval flag (-e/-c/...) let
// arbitrary code run despite policy nominally only permitting "node"/
// "python". A new, narrow interpreter-eval check now BLOCKs this specific,
// well-known pattern by default, independent of whether the interpreter
// itself is allowed. This is NOT a complete fix (see the module doc in
// resource-heuristics.js and SECURITY-ASSESSMENT.md) — it raises the bar
// against the single most blatant case, it does not close the general
// problem of allowing a general-purpose interpreter at all.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import yaml from 'js-yaml';

import { runExec } from '../../src/adapters/shell/exec-wrapper.js';
import { applyDefaults } from '../../src/core/policy-engine.js';

const DEFAULT_POLICY_PATH = path.join(process.cwd(), 'policy', 'default-policy.yaml');
const policy = applyDefaults(yaml.load(fs.readFileSync(DEFAULT_POLICY_PATH, 'utf8')));

test('F2 FIXED: agentguard exec -- node -e "<arbitrary code>" is now BLOCKED, even with an explicit shell.allowed', async () => {
  const allowingNode = applyDefaults({ shell: { allowed: ['node'] } });
  const marker = path.join(os.tmpdir(), `agentguard-f2-marker-${Date.now()}.txt`);
  if (fs.existsSync(marker)) fs.unlinkSync(marker);

  const payload = `require('fs').writeFileSync(process.argv[1], 'ARBITRARY_CODE_EXECUTED')`;
  const result = await runExec({ policy: allowingNode, command: 'node', args: ['-e', payload, marker] });

  assert.equal(result.decision.verdict, 'BLOCK', 'the interpreter-eval flag is caught even though "node" itself is allowed');
  assert.equal(result.decision.rule, 'shell.block_interpreter_eval');
  assert.equal(result.executed, false);
  assert.ok(!fs.existsSync(marker), 'the payload never ran - no marker file was written');
});

test('F2: "node" is no longer in the shipped default shell.allowed (defense in depth alongside the interpreter-eval check)', () => {
  assert.ok(!policy.shell.allowed.map((s) => s.toLowerCase()).includes('node'));
  assert.ok(!policy.shell.allowed.map((s) => s.toLowerCase()).includes('python'));
});

test('F2: a normal, non-eval invocation of an allowed interpreter is unaffected', async () => {
  const allowingNode = applyDefaults({ shell: { allowed: ['node'] } });
  const result = await runExec({ policy: allowingNode, command: 'node', args: ['--version'] });
  assert.equal(result.decision.verdict, 'ALLOW');
  assert.equal(result.executed, true);
});

test('F2: block_interpreter_eval can be explicitly disabled for a deployment that accepts the risk (WARN instead of BLOCK)', async () => {
  const permissive = applyDefaults({ shell: { allowed: ['node'], block_interpreter_eval: false } });
  const result = await runExec({ policy: permissive, command: 'node', args: ['-e', 'process.exit(0)'] });
  assert.equal(result.decision.verdict, 'WARN');
  assert.equal(result.executed, true);
});
