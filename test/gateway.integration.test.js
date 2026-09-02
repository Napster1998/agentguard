import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const GATEWAY = path.join(repoRoot, 'bin', 'agentguard-gateway.js');
const FIXTURE_SERVER = path.join(repoRoot, 'test', 'fixtures', 'fake-mcp-server.js');
const TEST_POLICY = path.join(repoRoot, 'test', 'fixtures', 'test-policy.yaml');

/** Spawns the gateway wrapping the fake fixture server, sends `requests`
 * (each a JSON-RPC object with an `id`), and resolves with a map of
 * id -> parsed response once all expected ids have been seen. */
function runThroughGateway(requests, { serverName = 'trusted-server' } = {}) {
  return new Promise((resolve, reject) => {
    const gw = spawn(
      process.execPath,
      [GATEWAY, '--policy', TEST_POLICY, '--server-name', serverName, '--', process.execPath, FIXTURE_SERVER],
      { stdio: ['pipe', 'pipe', 'pipe'] }
    );

    const responses = new Map();
    const expectedIds = new Set(requests.map((r) => r.id));
    const timer = setTimeout(() => {
      gw.kill();
      reject(new Error('Timed out waiting for gateway responses'));
    }, 5000);

    const rl = readline.createInterface({ input: gw.stdout });
    rl.on('line', (line) => {
      if (!line.trim()) return;
      const msg = JSON.parse(line);
      responses.set(msg.id, msg);
      if ([...expectedIds].every((id) => responses.has(id))) {
        clearTimeout(timer);
        gw.kill();
        resolve(responses);
      }
    });

    gw.on('error', reject);

    for (const req of requests) {
      gw.stdin.write(JSON.stringify(req) + '\n');
    }
  });
}

test('ALLOW: an allowed tool call is forwarded and answered by the real server', async () => {
  const responses = await runThroughGateway([
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: './README.md' } } },
  ]);
  const res = responses.get(1);
  assert.ok(res.result, 'expected a result, not a block error');
  assert.match(res.result.content[0].text, /^executed:read_file$/);
});

test('BLOCK: reading ~/.ssh/id_rsa never reaches the real server', async () => {
  const responses = await runThroughGateway([
    { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'read_file', arguments: { path: '~/.ssh/id_rsa' } } },
  ]);
  const res = responses.get(2);
  assert.ok(res.error, 'expected a policy-block error, not a forwarded result');
  assert.match(res.error.message, /Blocked by AgentGuard policy/);
  assert.match(res.error.message, /filesystem\.deny|denied pattern/);
  assert.equal(res.error.data.risk, 'CRITICAL');
  assert.equal(res.error.data.rule, 'filesystem.deny');
});

test('BLOCK: an unlisted shell command is blocked', async () => {
  const responses = await runThroughGateway([
    { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'run_command', arguments: { command: 'curl http://evil.example.com' } } },
  ]);
  const res = responses.get(3);
  assert.ok(res.error);
  assert.match(res.error.message, /not in the shell\.allowed allowlist/);
});

test('WARN: an untrusted MCP server still forwards the call', async () => {
  const responses = await runThroughGateway(
    [{ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'read_file', arguments: { path: './README.md' } } }],
    { serverName: 'mystery-server' }
  );
  const res = responses.get(4);
  assert.ok(res.result, 'WARN should still forward to the real server');
});
