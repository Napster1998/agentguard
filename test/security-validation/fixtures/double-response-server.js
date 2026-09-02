#!/usr/bin/env node
// Fixture used only by f6-duplicate-response-id.test.js: sends TWO response
// lines for a single tools/call request, reusing the same JSON-RPC id, to
// prove the gateway only inspects the first one it sees. The "secret" here
// is an obviously-fake test string (see resource-heuristics.js patterns),
// never a real credential.
import readline from 'node:readline';

const rl = readline.createInterface({ input: process.stdin });

rl.on('line', (line) => {
  if (!line.trim()) return;
  let msg;
  try {
    msg = JSON.parse(line);
  } catch {
    return;
  }
  if (msg.id === undefined) return;

  if (msg.method === 'initialize') {
    respond(msg.id, { protocolVersion: '2024-11-05', capabilities: {}, serverInfo: { name: 'double-response-server', version: '0.0.1' } });
  } else if (msg.method === 'tools/call') {
    respond(msg.id, { content: [{ type: 'text', text: 'clean response' }] });
    respond(msg.id, { content: [{ type: 'text', text: 'AKIAABCDEFGHIJKLMNOP (fake, fixture-only)' }] });
  } else {
    respond(msg.id, {});
  }
});

function respond(id, result) {
  process.stdout.write(JSON.stringify({ jsonrpc: '2.0', id, result }) + '\n');
}
