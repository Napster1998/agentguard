// Found on a real machine: after an AI app restarted, the gateway AND the MCP
// server behind it were still running (parent gone). A server launched
// directly by the app would have seen end-of-input and exited; behind the
// gateway it never did, because the gateway never reacted to its client
// disconnecting. Every app restart leaked a gateway plus a server process.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';

import { startProxy } from '../src/adapters/mcp/proxy.js';
import { applyDefaults } from '../src/core/policy-engine.js';

const fixtures = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');

function start(serverFile, extra = {}) {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const proxy = startProxy({
    policy: applyDefaults({}),
    serverCommand: process.execPath,
    serverArgs: [path.join(fixtures, serverFile)],
    logFile: null,
    serverName: 'lifecycle-test',
    stdin,
    stdout,
    ...extra,
  });
  return { stdin, stdout, ...proxy };
}

const within = (promise, ms, what) => {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`timed out waiting for: ${what}`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
};

// startProxy mirrors the server's exit code onto process.exitCode (correct for
// the real CLI). A force-stopped server exits non-zero, which would otherwise
// make THIS test process report failure.
after(() => {
  process.exitCode = 0;
});

test('when the client disconnects, a well-behaved server is told (EOF) and exits', async () => {
  const { stdin, child } = start('eof-server.js');
  assert.equal(child.exitCode, null, 'server is running');
  stdin.end(); // the client went away
  await within(once(child, 'exit'), 5000, 'server exit after client EOF');
  assert.notEqual(child.exitCode === null && child.signalCode === null, true, 'server is no longer running');
});

test('a server that ignores EOF is force-stopped shortly after its client disconnects', async () => {
  const { stdin, child } = start('stubborn-server.js', { shutdownGraceMs: 200 });
  stdin.end();
  await within(once(child, 'exit'), 5000, 'forced stop of a server that ignores EOF');
  assert.ok(child.exitCode !== null || child.signalCode !== null);
});

test('while the client stays connected the server is NOT stopped', async () => {
  const { stdin, child } = start('stubborn-server.js', { shutdownGraceMs: 200 });
  await new Promise((r) => setTimeout(r, 600));
  assert.equal(child.exitCode, null);
  assert.equal(child.signalCode, null, 'still running after longer than the grace period');
  stdin.end();
  await within(once(child, 'exit'), 5000, 'cleanup');
});
