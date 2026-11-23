// Spawns the real `agentguard hook antigravity` process, as Antigravity does,
// and checks the contract the Phase 6 spike established: Antigravity blocks a
// call when a hook exits non-zero, prints non-JSON, crashes or times out, and
// it shows the hook's stderr to the model. So the hook must ALWAYS print
// exactly one JSON line, exit 0, keep stderr empty, and turn anything it
// cannot handle into an explicit deny.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { real, sessionStart, WORKSPACE } from './fixtures/antigravity-payloads.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(root, 'bin', 'agentguard.js');
const POLICY = path.join(root, 'policy', 'default-policy.yaml');

function runHook(input, { args = ['--policy', POLICY], keepOpen = false } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentguard-hook-'));
  const log = path.join(dir, 'audit.jsonl');
  return new Promise((resolve) => {
    const started = Date.now();
    const child = spawn(process.execPath, [CLI, 'hook', 'antigravity', ...args, '--log', log], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => (stdout += c));
    child.stderr.on('data', (c) => (stderr += c));
    child.on('close', (code) => {
      const events = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse) : [];
      fs.rmSync(dir, { recursive: true, force: true });
      resolve({ code, stdout, stderr, events, ms: Date.now() - started });
    });
    if (input !== null) child.stdin.write(typeof input === 'string' ? input : JSON.stringify(input));
    if (!keepOpen) child.stdin.end();
  });
}

function assertContract(r, decision) {
  assert.equal(r.code, 0, 'always exit 0');
  assert.equal(r.stderr, '', 'nothing on stderr (Antigravity shows it to the model)');
  const lines = r.stdout.split('\n').filter(Boolean);
  assert.equal(lines.length, 1, `exactly one stdout line, got ${JSON.stringify(r.stdout)}`);
  const out = JSON.parse(lines[0]);
  if (decision) assert.equal(out.decision, decision);
  return out;
}

test('a credentials read is denied by the real CLI, logged before exit, with a clean contract', async () => {
  const r = await runHook(real.readFile(`${WORKSPACE}\\fake-creds\\.aws\\credentials`));
  const out = assertContract(r, 'deny');
  assert.match(out.reason, /Blocked by AgentGuard policy/);
  assert.equal(r.events.length, 1, 'the audit line is on disk when the process has exited');
  assert.equal(r.events[0].decision, 'BLOCK');
  assert.equal(r.events[0].source, 'antigravity-hook');
});

test('an ordinary call is allowed', async () => {
  assert.deepEqual(assertContract(await runHook(real.readFile()), 'allow'), { decision: 'allow' });
});

test('a lifecycle event gets {}', async () => {
  assert.deepEqual(assertContract(await runHook(sessionStart())), {});
});

test('bad input is denied, never allowed unevaluated: malformed, empty, oversize', async () => {
  for (const [input, fragment] of [
    ['{"hookEventName": "PreToolUse", ', 'not valid JSON'],
    ['', 'no input'],
    ['x'.repeat(1024 * 1024 + 10), 'larger than 1 MiB'],
  ]) {
    const out = assertContract(await runHook(input), 'deny');
    assert.ok(out.reason.includes(fragment), `"${out.reason}" should mention ${fragment}`);
  }
});

test('a broken setup is denied with a readable reason: no policy, missing policy file, invalid YAML', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'agentguard-hook-policy-'));
  const badYaml = path.join(dir, 'bad.yaml');
  fs.writeFileSync(badYaml, 'filesystem: [unclosed\n');
  try {
    const cases = [
      [[], 'no --policy'],
      [['--policy', path.join(dir, 'missing.yaml')], 'policy file could not be loaded'],
      [['--policy', badYaml], 'policy file could not be loaded'],
    ];
    for (const [args, fragment] of cases) {
      const r = await runHook(real.readFile(), { args });
      const out = assertContract(r, 'deny');
      assert.ok(out.reason.includes(fragment), `"${out.reason}" should mention ${fragment}`);
      assert.equal(r.events[0]?.rule, 'malformed-hook-input', 'the failure is in the audit log too');
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the internal deadline answers deny instead of hanging until Antigravity kills the hook', async () => {
  const r = await runHook('{"hookEventName":"PreTool', { args: ['--policy', POLICY, '--deadline-ms', '300'], keepOpen: true });
  const out = assertContract(r, 'deny');
  assert.match(out.reason, /did not finish within 300 ms/);
  assert.ok(r.ms < 4000, `answered in ${r.ms} ms`);
});

test('an unknown hook adapter is a usage error (exit 2), not a silent allow', async () => {
  const child = spawn(process.execPath, [CLI, 'hook', 'cursor', '--policy', POLICY]);
  let out = '';
  child.stdout.on('data', (c) => (out += c));
  const code = await new Promise((r) => child.on('close', r));
  assert.equal(code, 2);
  assert.equal(out, '');
});
