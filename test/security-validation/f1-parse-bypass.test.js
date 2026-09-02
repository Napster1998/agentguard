// F1 (CRITICAL, FIXED): a JSON-RPC line that fails JSON.parse used to be
// forwarded to the real MCP server WITHOUT ANY policy evaluation. It is now
// dropped (fail-closed) and logged as its own BLOCK audit event with rule
// "malformed-json" - proving policy is never silently bypassed by
// unparseable input, and that the drop itself is auditable.
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

test('F1 FIXED: malformed JSON is dropped (fail-closed), never forwarded, and logged as its own BLOCK event', async () => {
  const logFile = path.join(os.tmpdir(), `agentguard-f1-${Date.now()}.jsonl`);
  const gw = spawn(
    process.execPath,
    [GATEWAY, '--policy', TEST_POLICY, '--log', logFile, '--server-name', 'trusted-server', '--', process.execPath, FIXTURE_SERVER],
    { stdio: ['pipe', 'pipe', 'pipe'] }
  );

  const responses = new Map();
  const rl = readline.createInterface({ input: gw.stdout });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    const msg = JSON.parse(line);
    responses.set(msg.id, msg);
  });

  gw.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: './README.md' } } }) + '\n');
  // Malformed (trailing comma) - would be a ~/.ssh/id_rsa read if it parsed.
  gw.stdin.write('{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"~/.ssh/id_rsa"}},}\n');
  gw.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'read_file', arguments: { path: './package.json' } } }) + '\n');

  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out')), 5000);
    const check = setInterval(() => {
      if (responses.has(1) && responses.has(3)) {
        clearInterval(check);
        clearTimeout(timer);
        resolve();
      }
    }, 50);
  });
  gw.kill();

  assert.ok(responses.get(1).result, 'request 1 evaluated and forwarded normally');
  assert.ok(responses.get(3).result, 'request 3 evaluated and forwarded normally (gateway survived the malformed line)');
  assert.equal(responses.has(2), false, 'no response was ever produced for the malformed request - it was dropped, not forwarded');

  await new Promise((r) => setTimeout(r, 100));
  const events = fs
    .readFileSync(logFile, 'utf8')
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l));

  assert.equal(events.length, 3, 'the two real requests PLUS one event recording the dropped malformed line');
  const malformedEvent = events.find((e) => e.rule === 'malformed-json');
  assert.ok(malformedEvent, 'the drop itself is auditable');
  assert.equal(malformedEvent.decision, 'BLOCK');
  assert.ok(!events.some((e) => (e.resource || '').includes('.ssh')), 'the ~/.ssh path was never evaluated by policy - it never became a resource at all');
  fs.unlinkSync(logFile);
});
