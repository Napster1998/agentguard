import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const CLI = path.join(repoRoot, 'bin', 'agentguard.js');

test('agentguard scan --json runs end-to-end on the real host and prints a valid posture', async () => {
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'scan', '--json']);
  const posture = JSON.parse(stdout);
  assert.ok(Array.isArray(posture.findings));
  assert.ok(typeof posture.score === 'number');
});

test('agentguard scan (human-readable) prints the expected section headers', async () => {
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'scan']);
  assert.match(stdout, /AI Agent Security Scan/);
  assert.match(stdout, /Security Posture/);
  assert.match(stdout, /Overall:/);
});

test('agentguard events reads a real log file end-to-end', async () => {
  const file = path.join(os.tmpdir(), `agentguard-cli-events-${Date.now()}.jsonl`);
  fs.writeFileSync(
    file,
    JSON.stringify({ sessionId: 'cli-test', decision: 'ALLOW', risk: 'LOW', timestamp: '2026-01-01T00:00:00.000Z', toolName: 'read_file', resource: 'filesystem:./x.js', reason: '' }) + '\n'
  );
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'events', '--log', file]);
  assert.match(stdout, /Session cli-test/);
  fs.unlinkSync(file);
});

test('agentguard with no subcommand prints usage and exits 0', async () => {
  const { stderr } = await execFileAsync(process.execPath, [CLI]);
  assert.match(stderr, /Usage: agentguard/);
});

test('agentguard gateway subcommand proxies a real tools/call the same way agentguard-gateway.js does', async () => {
  const { spawn } = await import('node:child_process');
  const readline = await import('node:readline');

  const POLICY = path.join(repoRoot, 'test', 'fixtures', 'test-policy.yaml');
  const FIXTURE_SERVER = path.join(repoRoot, 'test', 'fixtures', 'fake-mcp-server.js');

  const gw = spawn(
    process.execPath,
    [CLI, 'gateway', '--policy', POLICY, '--server-name', 'trusted-server', '--', process.execPath, FIXTURE_SERVER],
    { stdio: ['pipe', 'pipe', 'pipe'] }
  );

  const response = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      gw.kill();
      reject(new Error('timed out'));
    }, 5000);
    const rl = readline.createInterface({ input: gw.stdout });
    rl.on('line', (line) => {
      if (!line.trim()) return;
      clearTimeout(timer);
      gw.kill();
      resolve(JSON.parse(line));
    });
    gw.stdin.write(
      JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: './README.md' } } }) + '\n'
    );
  });

  assert.ok(response.result, 'expected the call to be forwarded and answered');
});
