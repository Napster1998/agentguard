import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { resolveSpawnTarget, SpawnRefusal } from '../src/adapters/host/spawn-target.js';

const execFileAsync = promisify(execFile);
const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'agentguard.js');

// A fake Windows machine: which files "exist" on PATH.
const win = (files) => ({
  platform: 'win32',
  env: { PATH: 'C:\\bin;C:\\tools', ComSpec: 'C:\\Windows\\System32\\cmd.exe' },
  exists: (p) => files.includes(p.replace(/\//g, '\\')),
});

test('non-Windows platforms pass straight through', () => {
  assert.deepEqual(resolveSpawnTarget('npx', ['-y', 'x'], { platform: 'linux' }), { command: 'npx', args: ['-y', 'x'] });
  assert.deepEqual(resolveSpawnTarget('npx', [], { platform: 'darwin' }), { command: 'npx', args: [] });
});

test('Windows: real executables pass through unchanged', () => {
  assert.deepEqual(resolveSpawnTarget('node.exe', ['a'], win([])), { command: 'node.exe', args: ['a'] });
  assert.deepEqual(resolveSpawnTarget('node', ['a'], win(['C:\\bin\\node.exe'])), { command: 'node', args: ['a'] });
});

test('Windows: a bare `npx` that resolves to npx.cmd goes through cmd.exe /d /s /c', () => {
  const r = resolveSpawnTarget('npx', ['-y', '@scope/server', 'C:\\my dir'], win(['C:\\tools\\npx.cmd']));
  assert.deepEqual(r, { command: 'C:\\Windows\\System32\\cmd.exe', args: ['/d', '/s', '/c', 'npx', '-y', '@scope/server', 'C:\\my dir'] });
});

test('Windows: an explicit path to a .cmd/.bat script goes through cmd.exe too', () => {
  const r = resolveSpawnTarget('C:\\tools\\run.bat', ['x'], win(['C:\\tools\\run.bat']));
  assert.equal(r.args[3], 'C:\\tools\\run.bat');
});

test('Windows: a command that cannot be found is passed through so spawn() reports it honestly', () => {
  assert.deepEqual(resolveSpawnTarget('nope', ['a'], win([])), { command: 'nope', args: ['a'] });
});

test('Windows: arguments cmd.exe would interpret are REFUSED, not escaped', () => {
  for (const bad of ['a & calc', 'x | y', '>out.txt', '%PATH%', '^x', 'say "hi"', 'line\nbreak']) {
    assert.throws(
      () => resolveSpawnTarget('npx', [bad], win(['C:\\tools\\npx.cmd'])),
      (e) => e instanceof SpawnRefusal && /cmd\.exe would interpret/.test(e.message),
      JSON.stringify(bad)
    );
  }
});

test('Windows: a .cmd path containing a space is refused with an actionable message', () => {
  assert.throws(
    () => resolveSpawnTarget('C:\\Program Files\\x\\run.cmd', [], win(['C:\\Program Files\\x\\run.cmd'])),
    (e) => e instanceof SpawnRefusal && /space/.test(e.message)
  );
});

test('Windows, REAL: a .cmd shim launched via the resolver receives tricky arguments intact', { skip: process.platform !== 'win32' }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-shim-'));
  try {
    fs.writeFileSync(path.join(dir, 'echo.js'), 'process.stdout.write(JSON.stringify(process.argv.slice(2)))');
    fs.writeFileSync(path.join(dir, 'shim-echo.cmd'), `@"${process.execPath}" "%~dp0echo.js" %*\r\n`);
    const args = ['two words', 'ünï-çödé', 'k=v', '--flag'];

    // The resolver and spawn() must see the SAME environment (in the gateway
    // both use process.env), so build it once and hand it to both.
    const env = { ...process.env, PATH: `${dir};${process.env.PATH}` };
    const target = resolveSpawnTarget('shim-echo', args, { env });
    assert.match(target.command, /cmd\.exe$/i, 'routed through cmd.exe');

    const child = spawn(target.command, target.args, { stdio: ['ignore', 'pipe', 'pipe'], env });
    let out = '';
    child.stdout.on('data', (d) => (out += d));
    await new Promise((r) => child.on('close', r));
    assert.deepEqual(JSON.parse(out), args);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('gateway with a server command that does not exist: one clean line and exit 1, no stack trace', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-gw-'));
  try {
    const policy = path.join(dir, 'p.yaml');
    fs.writeFileSync(policy, 'mcp:\n  allowed_servers: []\n');
    let res;
    try {
      res = await execFileAsync(process.execPath, [CLI, 'gateway', '--policy', policy, '--', 'definitely-not-a-real-command-xyz'], {
        timeout: 15000,
      });
      res.code = 0;
    } catch (e) {
      res = e;
    }
    assert.equal(res.code, 1);
    assert.match(res.stderr, /could not start the MCP server "definitely-not-a-real-command-xyz": ENOENT/);
    assert.ok(!/at .*\(.*:\d+:\d+\)/.test(res.stderr), 'no stack trace');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
