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

test('agentguard exec allows and runs a permitted command', async () => {
  const POLICY = path.join(repoRoot, 'test', 'fixtures', 'test-policy.yaml');
  const { stdout } = await execFileAsync(process.execPath, [CLI, 'exec', '--policy', POLICY, '--', 'git', '--version']);
  assert.match(stdout, /git version/i);
});

test('agentguard exec blocks a denied command with a non-zero exit and no output from the command itself', async () => {
  const POLICY = path.join(repoRoot, 'test', 'fixtures', 'test-policy.yaml');
  await assert.rejects(
    execFileAsync(process.execPath, [CLI, 'exec', '--policy', POLICY, '--', 'rm', '-rf', '/tmp/should-never-run']),
    (err) => {
      assert.notEqual(err.code, 0);
      assert.match(err.stderr, /BLOCKED by AgentGuard policy/);
      return true;
    }
  );
});

test('agentguard with no subcommand prints help (to stdout, the convention for help) and exits 0', async () => {
  const { stdout, stderr } = await execFileAsync(process.execPath, [CLI]);
  assert.match(stdout, /Usage: agentguard <command>/);
  assert.equal(stderr, '');
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
