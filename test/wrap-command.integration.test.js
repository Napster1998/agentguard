// End-to-end tests of `agentguard wrap | status | unwrap` as real subprocesses.
// Every test runs inside a SANDBOX: a throwaway fake home directory (HOME,
// USERPROFILE, APPDATA, AGENTGUARD_HOME all point into it), so these tests
// can never read or modify a real user's client configs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import readline from 'node:readline';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { clientConfigs } from '../src/adapters/discovery/client-configs.js';

const execFileAsync = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(here, '..', 'bin', 'agentguard.js');
const FIXTURE = path.join(here, 'fixtures', 'fake-mcp-server.js');
const realHome = os.homedir();

function sandbox() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-wrap-'));
  const home = path.join(root, 'home');
  const project = path.join(root, 'project');
  fs.mkdirSync(project, { recursive: true });
  const env = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    APPDATA: path.join(home, 'AppData', 'Roaming'),
    AGENTGUARD_HOME: path.join(home, '.agentguard'),
  };
  assert.notEqual(path.resolve(home), path.resolve(realHome), 'sandbox must never be the real home');
  const clients = Object.fromEntries(clientConfigs({ cwd: project, homedir: home, env }).map((c) => [c.id, c.path]));
  const put = (file, obj) => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2) + '\n');
  };
  const run = async (args, { cwd = project } = {}) => {
    try {
      const { stdout } = await execFileAsync(process.execPath, [CLI, ...args], { env, cwd });
      return { code: 0, stdout };
    } catch (e) {
      return { code: e.code, stdout: e.stdout || '', stderr: e.stderr || '' };
    }
  };
  return { root, home, project, env, clients, put, run, cleanup: () => fs.rmSync(root, { recursive: true, force: true }) };
}

const sha = (f) => crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');
const server = { command: process.execPath, args: [FIXTURE] };

test('preview changes nothing; apply wraps supported clients; Claude Code user file is never touched; apply is idempotent; unwrap restores bytes', async () => {
  const sb = sandbox();
  try {
    const bigClaudeJson = { numStartups: 7, projects: { '/x': { history: ['a', 'b'] } }, mcpServers: { userScoped: server } };
    sb.put(sb.clients['antigravity'], { mcpServers: { burpsuite: { ...server, env: { K: 'v' } } } });
    sb.put(sb.clients['claude-desktop'], { mcpServers: { files: server, remote: { url: 'https://example.com/mcp' } }, other: 1 });
    sb.put(sb.clients['claude-code-project'], { mcpServers: { projsrv: server } });
    sb.put(sb.clients['claude-code-user'], bigClaudeJson);
    const files = Object.values(sb.clients);
    const before = Object.fromEntries(files.map((f) => [f, sha(f)]));

    // preview
    const preview = await sb.run(['wrap']);
    assert.equal(preview.code, 0);
    assert.match(preview.stdout, /preview/);
    assert.match(preview.stdout, /will wrap\s+burpsuite/);
    assert.match(preview.stdout, /remote \(HTTP\/SSE\) servers are not supported/);
    assert.match(preview.stdout, /not managed.*owned and continuously rewritten/);
    assert.ok(!preview.stdout.includes('"K"') && !preview.stdout.includes('v"'), 'env values are never printed');
    for (const f of files) assert.equal(sha(f), before[f], 'preview wrote nothing');
    assert.equal(fs.existsSync(sb.env.AGENTGUARD_HOME), false, 'preview created no state directory');

    // apply
    const applied = await sb.run(['wrap', '--apply']);
    assert.equal(applied.code, 0, applied.stdout);
    assert.match(applied.stdout, /created policy/);
    assert.equal(sha(sb.clients['claude-code-user']), before[sb.clients['claude-code-user']], '~/.claude.json untouched');
    for (const id of ['antigravity', 'claude-desktop', 'claude-code-project']) assert.notEqual(sha(sb.clients[id]), before[sb.clients[id]], id);
    const desktop = JSON.parse(fs.readFileSync(sb.clients['claude-desktop'], 'utf8'));
    assert.equal(desktop.other, 1, 'unrelated keys preserved');
    assert.deepEqual(desktop.mcpServers.remote, { url: 'https://example.com/mcp' }, 'remote server left as-is');
    assert.equal(desktop.mcpServers.files.command, process.execPath);
    const ag = JSON.parse(fs.readFileSync(sb.clients['antigravity'], 'utf8'));
    assert.deepEqual(ag.mcpServers.burpsuite.env, { K: 'v' }, 'env preserved');
    const policy = fs.readFileSync(path.join(sb.env.AGENTGUARD_HOME, 'policy.yaml'), 'utf8');
    assert.match(policy, /burpsuite/);
    assert.match(policy, /files/);
    assert.equal(fs.readdirSync(path.join(sb.env.AGENTGUARD_HOME, 'backups')).length, 3, 'one backup per rewritten file');

    // status
    const status = await sb.run(['status']);
    assert.match(status.stdout, /✓ burpsuite\s+protected/);
    assert.match(status.stdout, /NOT protected: remote/);
    assert.match(status.stdout, /Claude Code \(user settings\).*not managed/);
    assert.match(status.stdout, /3 protected, 2 not protected/); // userScoped + remote

    // idempotent
    const afterApply = Object.fromEntries(files.map((f) => [f, sha(f)]));
    const again = await sb.run(['wrap', '--apply']);
    assert.match(again.stdout, /Nothing to wrap/);
    for (const f of files) assert.equal(sha(f), afterApply[f], 'second apply changed nothing');

    // unwrap restores the original bytes
    const un = await sb.run(['unwrap', '--apply']);
    assert.equal(un.code, 0, un.stdout);
    for (const f of files) assert.equal(sha(f), before[f], `restored byte-for-byte: ${path.basename(f)}`);
  } finally {
    sb.cleanup();
  }
});

test('END TO END: a wrapped entry, spawned exactly as a client would, enforces policy and `agentguard events` shows it', async () => {
  const sb = sandbox();
  try {
    sb.put(sb.clients['antigravity'], { mcpServers: { files: server } });
    assert.equal((await sb.run(['wrap', '--apply'])).code, 0);

    const entry = JSON.parse(fs.readFileSync(sb.clients['antigravity'], 'utf8')).mcpServers.files;
    const child = spawn(entry.command, entry.args, { stdio: ['pipe', 'pipe', 'ignore'], env: sb.env });
    const waiters = new Map();
    readline.createInterface({ input: child.stdout }).on('line', (l) => {
      try {
        const m = JSON.parse(l);
        waiters.get(m.id)?.(m);
      } catch {
        /* ignore non-JSON */
      }
    });
    const rpc = (id, method, params) =>
      new Promise((resolve, reject) => {
        const t = setTimeout(() => reject(new Error(`timeout on ${method}`)), 8000);
        waiters.set(id, (m) => {
          clearTimeout(t);
          resolve(m);
        });
        child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
      });

    await rpc(1, 'initialize', { protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'e2e-client', version: '1' } });
    const ok = await rpc(2, 'tools/call', { name: 'read_file', arguments: { path: './README.md' } });
    assert.ok(ok.result, 'an ordinary call passes through to the real server');
    const blocked = await rpc(3, 'tools/call', { name: 'read_file', arguments: { path: '~/.ssh/id_rsa' } });
    assert.equal(blocked.error?.code, -32001);
    assert.match(blocked.error.message, /Blocked by AgentGuard policy/);
    child.kill();
    await new Promise((r) => setTimeout(r, 200));

    const events = await sb.run(['events']); // no --log: shared default
    assert.match(events.stdout, /ALLOW/);
    assert.match(events.stdout, /BLOCK/);
    assert.match(events.stdout, /id_rsa/);
  } finally {
    sb.cleanup();
  }
});

test('an unparseable config is skipped and left untouched while a good one is still wrapped', async () => {
  const sb = sandbox();
  try {
    const bad = path.join(sb.root, 'bad.json');
    const good = path.join(sb.root, 'good.json');
    fs.writeFileSync(bad, '{ not json');
    sb.put(good, { mcpServers: { s: server } });
    const r = await sb.run(['wrap', '--apply', '--config', bad, '--config', good]);
    assert.equal(r.code, 0);
    assert.match(r.stdout, /not valid JSON/);
    assert.equal(fs.readFileSync(bad, 'utf8'), '{ not json');
    assert.equal(JSON.parse(fs.readFileSync(good, 'utf8')).mcpServers.s.command, process.execPath);
  } finally {
    sb.cleanup();
  }
});

test('an empty config (a freshly installed app) is "no servers", and wrap leaves it alone', async () => {
  const sb = sandbox();
  try {
    sb.put(sb.clients['antigravity'], '');
    const r = await sb.run(['wrap', '--apply']);
    assert.match(r.stdout, /no MCP servers configured/);
    assert.equal(fs.readFileSync(sb.clients['antigravity'], 'utf8'), '');
  } finally {
    sb.cleanup();
  }
});

test('--project finds a project .mcp.json outside the current folder', async () => {
  const sb = sandbox();
  try {
    const elsewhere = path.join(sb.root, 'elsewhere');
    fs.mkdirSync(elsewhere);
    sb.put(path.join(elsewhere, '.mcp.json'), { mcpServers: { projsrv: server } });
    const r = await sb.run(['wrap', '--client', 'claude-code-project', '--project', elsewhere]);
    assert.match(r.stdout, /will wrap\s+projsrv/);
  } finally {
    sb.cleanup();
  }
});

test('bad usage exits 2 and changes nothing', async () => {
  const sb = sandbox();
  try {
    assert.equal((await sb.run(['wrap', '--aply'])).code, 2);
    assert.equal((await sb.run(['wrap', '--client', 'nonesuch'])).code, 2);
    assert.equal((await sb.run(['unwrap', '--config'])).code, 2);
    assert.equal(fs.existsSync(sb.env.AGENTGUARD_HOME), false);
  } finally {
    sb.cleanup();
  }
});

test('status flags a wrapper that points at a different install, and wrap --apply repairs it', async () => {
  const sb = sandbox();
  try {
    sb.put(sb.clients['antigravity'], { mcpServers: { files: server } });
    await sb.run(['wrap', '--apply']);
    const f = sb.clients['antigravity'];
    const cfg = JSON.parse(fs.readFileSync(f, 'utf8'));
    cfg.mcpServers.files.args[0] = path.join(sb.root, 'moved-away', 'bin', 'agentguard.js'); // simulates a moved repo
    sb.put(f, cfg);

    const status = await sb.run(['status']);
    assert.match(status.stdout, /needs repair/);
    assert.match(status.stdout, /Problems/);

    const fixed = await sb.run(['wrap', '--apply']);
    assert.match(fixed.stdout, /repair/);
    const status2 = await sb.run(['status']);
    assert.match(status2.stdout, /✓ files\s+protected/);
    assert.ok(!/Problems/.test(status2.stdout));
  } finally {
    sb.cleanup();
  }
});
