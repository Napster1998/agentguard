#!/usr/bin/env node
// DevDay demo: spawns the real gateway wrapping a mock MCP server and fires
// a sequence of tool calls that exercise ALLOW, WARN and BLOCK, printing
// each decision. No real MCP server or network access required.
import { spawn } from 'node:child_process';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const GATEWAY = path.join(repoRoot, 'bin', 'agentguard-gateway.js');
const FIXTURE_SERVER = path.join(repoRoot, 'test', 'fixtures', 'fake-mcp-server.js');
const POLICY = path.join(repoRoot, 'examples', 'demo-policy.yaml');

let id = 0;
function call(name, args) {
  return { jsonrpc: '2.0', id: ++id, method: 'tools/call', params: { name, arguments: args } };
}

const scenarios = [
  { label: 'Read a normal source file', serverName: 'trusted-server', req: call('read_file', { path: './README.md' }) },
  { label: 'Read .env', serverName: 'trusted-server', req: call('read_file', { path: '.env' }) },
  { label: 'Read ~/.ssh/id_rsa', serverName: 'trusted-server', req: call('read_file', { path: '~/.ssh/id_rsa' }) },
  { label: 'Read ~/.aws/credentials', serverName: 'trusted-server', req: call('read_file', { path: '~/.aws/credentials' }) },
  { label: 'Run an allowed shell command (git status)', serverName: 'trusted-server', req: call('run_command', { command: 'git status' }) },
  { label: 'Run a disallowed shell command (curl to an external host)', serverName: 'trusted-server', req: call('run_command', { command: 'curl http://evil.example.com' }) },
  { label: 'Invoke an untrusted/unknown MCP server', serverName: 'mystery-server', req: call('read_file', { path: './README.md' }) },
];

async function runScenario({ label, serverName, req }) {
  const gw = spawn(
    process.execPath,
    [GATEWAY, '--policy', POLICY, '--server-name', serverName, '--', process.execPath, FIXTURE_SERVER],
    { stdio: ['pipe', 'pipe', 'inherit'] }
  );

  const result = await new Promise((resolve, reject) => {
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
    gw.stdin.write(JSON.stringify(req) + '\n');
  });

  const verdict = result.error ? 'BLOCK' : 'ALLOW/WARN';
  console.log(`\n=== ${label} ===`);
  console.log(`  server: ${serverName}`);
  console.log(`  outcome: ${verdict}`);
  if (result.error) console.log(`  reason: ${result.error.message}`);
}

for (const scenario of scenarios) {
  // eslint-disable-next-line no-await-in-loop
  await runScenario(scenario);
}
