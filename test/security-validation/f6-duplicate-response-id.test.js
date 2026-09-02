// F6 (MEDIUM, FIXED): pendingRequests used to be consulted with a
// `!pending ||` shortcut that skipped inspection entirely for a response
// with an untracked/already-consumed id. The gateway now inspects EVERY
// response carrying a `result`, tracked or not - proving a second response
// reusing the same id (only a malicious/compromised downstream server would
// send this) no longer bypasses inspection.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..');
const GATEWAY = path.join(repoRoot, 'bin', 'agentguard-gateway.js');
const FIXTURE_SERVER = path.join(__dirname, 'fixtures', 'double-response-server.js');
const TEST_POLICY = path.join(repoRoot, 'test', 'fixtures', 'test-policy.yaml');

test('F6 FIXED: a second response reusing the same id is now inspected and BLOCKed too', async () => {
  const gw = spawn(
    process.execPath,
    [GATEWAY, '--policy', TEST_POLICY, '--server-name', 'trusted-server', '--', process.execPath, FIXTURE_SERVER],
    { stdio: ['pipe', 'pipe', 'pipe'] }
  );

  const received = [];
  const rl = readline.createInterface({ input: gw.stdout });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    received.push(JSON.parse(line));
  });

  gw.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'leak', arguments: {} } }) + '\n');

  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out waiting for two responses')), 5000);
    const check = setInterval(() => {
      if (received.length >= 2) {
        clearInterval(check);
        clearTimeout(timer);
        resolve();
      }
    }, 50);
  });
  gw.kill();

  assert.equal(received.length, 2);
  const [first, second] = received;

  assert.ok(first.result, 'the first (clean) response is inspected and forwarded normally');
  assert.match(first.result.content[0].text, /clean response/);

  // The fix: the second response, containing the fake secret, is now
  // BLOCKed even though its id was already "consumed" by the first one.
  assert.ok(second.error, 'the second (secret-containing) response is now BLOCKed, not silently forwarded');
  assert.match(second.error.message, /Response blocked by AgentGuard policy/);
  assert.equal(second.error.data.risk, 'CRITICAL');
});
