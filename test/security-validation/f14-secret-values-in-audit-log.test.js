// F14 (MEDIUM, FIXED): found during the Phase 6 (Antigravity hooks) feasibility
// review, not by the existing tests. The claim "secret values never appear in
// AgentGuard's own logs" was verified only for one gateway case (a secret under
// a non-path key). Two other paths wrote the raw value:
//   - `agentguard exec` records `metadata.args`, the raw argv, so a BLOCKed
//     `git commit -m "<key>"` put the key in the audit log;
//   - the gateway's `resource` summary and `subDecisions` carry each
//     classified value verbatim, so a secret inside a path-shaped argument
//     (anything with a "/") was logged as part of a "filesystem:" value;
//   - the interpreter-eval reason quotes the whole command line.
// Fix: createSecurityEvent, the one place every adapter's event is built,
// replaces every secret-pattern match in every recorded string with
// "[REDACTED:<pattern name>]". Policy evaluation still sees the raw value; only
// the record (JSONL + stderr mirror) is redacted.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

import { runExec } from '../../src/adapters/shell/exec-wrapper.js';
import { applyDefaults } from '../../src/core/policy-engine.js';
import { createSecurityEvent } from '../../src/core/security-event.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const GATEWAY = path.join(repoRoot, 'bin', 'agentguard-gateway.js');
const FIXTURE_SERVER = path.join(repoRoot, 'test', 'fixtures', 'fake-mcp-server.js');
const TEST_POLICY = path.join(repoRoot, 'test', 'fixtures', 'test-policy.yaml');

// AWS's own documentation example key: fake, matches the aws-access-key-id pattern.
const FAKE_KEY = 'AKIAIOSFODNN7EXAMPLE';
const tmpLog = (tag) => path.join(os.tmpdir(), `agentguard-f14-${tag}-${process.pid}-${Date.now()}.jsonl`);

test('F14 FIXED: agentguard exec no longer writes a secret from argv into the audit log', async () => {
  const logFile = tmpLog('exec');
  try {
    const result = await runExec({
      policy: applyDefaults({ shell: { allowed: ['git'] } }),
      command: 'git',
      args: ['commit', '-m', `key ${FAKE_KEY}`],
      logFile,
    });
    assert.equal(result.executed, false, 'still BLOCKed: evaluation saw the raw value');
    assert.equal(result.decision.rule, 'secrets.block_exfiltration');

    const text = fs.readFileSync(logFile, 'utf8');
    assert.ok(!text.includes(FAKE_KEY), 'the raw key is not in the audit log');
    const event = JSON.parse(text.trim());
    assert.deepEqual(event.metadata.args, ['commit', '-m', 'key [REDACTED:aws-access-key-id]'], 'args are kept, with only the secret replaced');
  } finally {
    fs.rmSync(logFile, { force: true });
  }
});

test('F14 FIXED: an interpreter-eval reason that quotes the command line is redacted too', async () => {
  const logFile = tmpLog('eval');
  try {
    const result = await runExec({
      policy: applyDefaults({ shell: { allowed: ['node'] } }),
      command: 'node',
      args: ['-e', `console.log("${FAKE_KEY}")`],
      logFile,
    });
    assert.equal(result.executed, false);
    assert.ok(!fs.readFileSync(logFile, 'utf8').includes(FAKE_KEY));
  } finally {
    fs.rmSync(logFile, { force: true });
  }
});

test('F14 FIXED: a secret inside a path-shaped MCP argument never reaches the gateway log or stderr', async () => {
  const logFile = tmpLog('gateway');
  const gw = spawn(
    process.execPath,
    [GATEWAY, '--policy', TEST_POLICY, '--log', logFile, '--server-name', 'trusted-server', '--', process.execPath, FIXTURE_SERVER],
    { stdio: ['pipe', 'pipe', 'pipe'] }
  );
  let stderr = '';
  gw.stderr.on('data', (c) => (stderr += c.toString()));
  try {
    const response = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timed out')), 5000);
      readline.createInterface({ input: gw.stdout }).on('line', (line) => {
        if (!line.trim()) return;
        clearTimeout(timer);
        resolve(JSON.parse(line));
      });
      gw.stdin.write(
        JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'tools/call',
          params: { name: 'read_file', arguments: { path: `/tmp/${FAKE_KEY}/notes.txt` } },
        }) + '\n'
      );
    });
    assert.ok(response.error, 'BLOCKed by the secret rule');
    const text = fs.readFileSync(logFile, 'utf8');
    assert.ok(!text.includes(FAKE_KEY), 'not in resource, subDecisions or anywhere else in the log');
    assert.ok(text.includes('[REDACTED:aws-access-key-id]'), 'the path is still recorded, with the secret replaced');
    assert.ok(!stderr.includes(FAKE_KEY), 'not in the human-readable stderr mirror');
  } finally {
    gw.kill();
    fs.rmSync(logFile, { force: true });
  }
});

test('F14: redaction covers every recorded field, nested values included, and leaves clean values untouched', () => {
  const pem = '-----BEGIN RSA PRIVATE KEY-----';
  const assignment = 'api_key = "abcdefghijklmnopqrstuvwx"';
  const event = createSecurityEvent({
    sessionId: 's',
    source: 'test',
    decision: 'BLOCK',
    risk: 'CRITICAL',
    resource: `filesystem:/x/${FAKE_KEY}`,
    destination: `${FAKE_KEY}.example`,
    reason: `quoted ${pem}`,
    subDecisions: [{ value: assignment }],
    metadata: { cwd: '/repo', nested: { list: ['plain', `a ${FAKE_KEY} b`] } },
  });
  const text = JSON.stringify(event);
  for (const raw of [FAKE_KEY, pem, assignment]) assert.ok(!text.includes(raw), `${raw} must be redacted`);
  assert.equal(event.metadata.cwd, '/repo');
  assert.equal(event.metadata.nested.list[0], 'plain');
  assert.equal(event.metadata.nested.list[1], 'a [REDACTED:aws-access-key-id] b');
  assert.equal(event.subDecisions[0].value, '[REDACTED:generic-secret-assignment]');
});
