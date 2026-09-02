import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import yaml from 'js-yaml';

import { runExec } from '../src/adapters/shell/exec-wrapper.js';
import { applyDefaults } from '../src/core/policy-engine.js';

const TEST_POLICY_PATH = path.join(process.cwd(), 'test', 'fixtures', 'test-policy.yaml');
const policy = applyDefaults(yaml.load(fs.readFileSync(TEST_POLICY_PATH, 'utf8')));

test('an allowed command actually executes (real prevention requires real execution when ALLOWED)', async () => {
  const result = await runExec({ policy, command: 'git', args: ['--version'] });
  assert.equal(result.executed, true);
  assert.equal(result.exitCode, 0);
  assert.equal(result.decision.verdict, 'ALLOW');
});

test('a shell.deny binary is BLOCKED and never spawned', async () => {
  const result = await runExec({ policy, command: 'rm', args: ['-rf', '/tmp/nonexistent-marker-should-never-run'] });
  assert.equal(result.executed, false);
  assert.equal(result.decision.verdict, 'BLOCK');
  assert.equal(result.decision.rule, 'shell.deny');
});

test('an allowed binary with a denied filesystem argument is still BLOCKED and never spawned', async () => {
  const result = await runExec({ policy, command: 'npm', args: ['pack', '~/.ssh/id_rsa'] });
  assert.equal(result.executed, false);
  assert.equal(result.decision.verdict, 'BLOCK');
  assert.equal(result.decision.rule, 'filesystem.deny');
});

test('an unlisted binary (not in shell.allowed) is BLOCKED and never spawned', async () => {
  const result = await runExec({ policy, command: 'curl', args: ['http://evil.example.com'] });
  assert.equal(result.executed, false);
  assert.equal(result.decision.verdict, 'BLOCK');
});

test('every run writes a SecurityEvent to the log with source shell-exec and cwd/args metadata', async () => {
  const logFile = path.join(os.tmpdir(), `agentguard-exec-test-${Date.now()}.jsonl`);
  await runExec({ policy, command: 'git', args: ['--version'], logFile, cwd: process.cwd() });

  const lines = fs.readFileSync(logFile, 'utf8').trim().split('\n');
  const event = JSON.parse(lines[lines.length - 1]);
  assert.equal(event.source, 'shell-exec');
  assert.equal(event.actionType, 'SHELL_EXEC');
  assert.equal(event.metadata.cwd, process.cwd());
  assert.deepEqual(event.metadata.args, ['--version']);
  fs.unlinkSync(logFile);
});
