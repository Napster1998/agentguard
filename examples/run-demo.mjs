#!/usr/bin/env node
// DevDay demo: DISCOVER -> ASSESS -> (agent runs) -> OBSERVE -> EVALUATE ->
// ENFORCE -> AUDIT. Runs `agentguard scan` for a posture snapshot, then
// spawns the real gateway wrapping a mock MCP server and fires a sequence
// of tool calls exercising ALLOW/WARN/BLOCK, then `agentguard events` to
// show the resulting audit trail through the CLI. No real MCP server,
// network access, or anything actually installed on the host is required
// for the gateway portion; `agentguard scan` inspects whatever is really
// on this machine.
import { spawn } from 'node:child_process';
import path from 'node:path';
import readline from 'node:readline';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

import { runScanCommand } from '../src/cli/scan-command.js';
import { runEventsCommand } from '../src/cli/events-command.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const CLI = path.join(repoRoot, 'bin', 'agentguard.js');
const FIXTURE_SERVER = path.join(repoRoot, 'test', 'fixtures', 'fake-mcp-server.js');
const POLICY = path.join(repoRoot, 'examples', 'demo-policy.yaml');
const LOG_FILE = path.join(os.tmpdir(), `agentguard-demo-${Date.now()}.jsonl`);

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

/** Runs every scenario for one serverName through a single long-lived
 * gateway process, so they land in the same audit sessionId — this is what
 * lets `agentguard events` show "what did this agent do this session". */
async function runGroup(serverName, group) {
  const gw = spawn(
    process.execPath,
    [CLI, 'gateway', '--policy', POLICY, '--log', LOG_FILE, '--server-name', serverName, '--', process.execPath, FIXTURE_SERVER],
    { stdio: ['pipe', 'pipe', 'inherit'] }
  );

  const pending = new Map();
  const rl = readline.createInterface({ input: gw.stdout });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    const msg = JSON.parse(line);
    pending.get(msg.id)?.(msg);
  });

  for (const { label, req } of group) {
    // eslint-disable-next-line no-await-in-loop
    const result = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timed out')), 5000);
      pending.set(req.id, (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      gw.stdin.write(JSON.stringify(req) + '\n');
    });

    const verdict = result.error ? 'BLOCK' : 'ALLOW/WARN';
    console.log(`\n=== ${label} ===`);
    console.log(`  server: ${serverName}`);
    console.log(`  outcome: ${verdict}`);
    if (result.error) console.log(`  reason: ${result.error.message}`);
  }

  gw.kill();
}

console.log('\n########################################');
console.log('# STEP 1: DISCOVER + ASSESS (agentguard scan)');
console.log('########################################\n');
await runScanCommand([]);

console.log('\n########################################');
console.log('# STEP 2: OBSERVE + EVALUATE + ENFORCE (agent runs through the gateway)');
console.log('########################################');

const byServer = new Map();
for (const scenario of scenarios) {
  if (!byServer.has(scenario.serverName)) byServer.set(scenario.serverName, []);
  byServer.get(scenario.serverName).push(scenario);
}
for (const [serverName, group] of byServer) {
  // eslint-disable-next-line no-await-in-loop
  await runGroup(serverName, group);
}

console.log('\n########################################');
console.log('# STEP 3: AUDIT (agentguard events)');
console.log('########################################\n');
runEventsCommand(['--log', LOG_FILE]);

fs.unlinkSync(LOG_FILE);
