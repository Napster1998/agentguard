// Attack Area 8: does AgentGuard itself ever leak sensitive data through
// its own logging/inspection? This sweeps the audit log, the human-readable
// stderr output, and the JSON-RPC error sent back to the agent for the
// literal fake-secret text, proving only the PATTERN NAME (e.g.
// "aws-access-key-id") is ever recorded, never the matched value itself.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..');
const GATEWAY = path.join(repoRoot, 'bin', 'agentguard-gateway.js');
const FIXTURE_SERVER = path.join(repoRoot, 'test', 'fixtures', 'fake-mcp-server.js');
const TEST_POLICY = path.join(repoRoot, 'test', 'fixtures', 'test-policy.yaml');

const FAKE_SECRET = 'AKIAABCDEFGHIJKLMNOP'; // fake, matches the aws-access-key-id pattern only

test('a fake secret in a request argument never appears in the audit log, stderr, or the JSON-RPC error itself', async () => {
  const logFile = path.join(os.tmpdir(), `agentguard-secret-leak-${Date.now()}.jsonl`);
  const gw = spawn(
    process.execPath,
    [GATEWAY, '--policy', TEST_POLICY, '--log', logFile, '--server-name', 'trusted-server', '--', process.execPath, FIXTURE_SERVER],
    { stdio: ['pipe', 'pipe', 'pipe'] }
  );

  let stderrOutput = '';
  gw.stderr.on('data', (chunk) => {
    stderrOutput += chunk.toString();
  });

  const response = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out')), 5000);
    const rl = readline.createInterface({ input: gw.stdout });
    rl.on('line', (line) => {
      if (!line.trim()) return;
      clearTimeout(timer);
      resolve(JSON.parse(line));
    });
    gw.stdin.write(
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'write_file', arguments: { content: `key=${FAKE_SECRET}` } },
      }) + '\n'
    );
  });
  gw.kill();

  assert.ok(response.error, 'the secret-bearing call should have been BLOCKed');
  assert.ok(!response.error.message.includes(FAKE_SECRET), 'the JSON-RPC error message does not contain the raw secret');
  assert.ok(!stderrOutput.includes(FAKE_SECRET), 'stderr human-readable output does not contain the raw secret');

  await new Promise((r) => setTimeout(r, 100)); // let the sync log write settle
  const logContent = fs.readFileSync(logFile, 'utf8');
  assert.ok(!logContent.includes(FAKE_SECRET), 'the JSONL audit log does not contain the raw secret');
  assert.ok(logContent.includes('aws-access-key-id'), 'the log DOES record the pattern name, which is the intended, safe signal');

  fs.unlinkSync(logFile);
});
