// Phase 6.4: `agentguard hooks` install / remove / status, always in a
// sandboxed HOME / USERPROFILE / AGENTGUARD_HOME so the real machine's
// Antigravity and AgentGuard configuration are never read or written.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import yaml from 'js-yaml';
import { fileURLToPath } from 'node:url';

import { runHooksCommand } from '../src/cli/hooks-command.js';
import { buildHookCommand, readHooksState } from '../src/adapters/antigravity/hooks-config.js';
import { PolicyEngine, applyDefaults } from '../src/core/policy-engine.js';
import { handleHookInput } from '../src/adapters/antigravity/hook-handler.js';
import { real } from './fixtures/antigravity-payloads.js';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const CLI = path.join(root, 'bin', 'agentguard.js');

function sandbox() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'agentguard-hooks-home-'));
  const workspace = path.join(home, 'project');
  fs.mkdirSync(workspace);
  const agHome = path.join(home, '.agentguard');
  const env = {
    ...process.env,
    // `node --test` in a real terminal sets FORCE_COLOR for its children; with
    // NO_COLOR also set, Node prints a warning on stderr (found on Linux).
    FORCE_COLOR: undefined,
    HOME: home,
    USERPROFILE: home,
    APPDATA: path.join(home, 'AppData', 'Roaming'),
    LOCALAPPDATA: path.join(home, 'AppData', 'Local'),
    AGENTGUARD_HOME: agHome,
    NO_COLOR: '1',
  };
  return { home, workspace, agHome, env, hooksFile: path.join(workspace, '.agents', 'hooks.json'), cleanup: () => fs.rmSync(home, { recursive: true, force: true }) };
}

const cli = (args, env) => spawnSync(process.execPath, [CLI, ...args], { env, encoding: 'utf8' });

/** Runs the installed hook command exactly as Antigravity does, with one payload. */
function runInstalledHook(command, payload) {
  const child =
    process.platform === 'win32'
      ? spawn('cmd.exe', ['/s', '/c', `"${command}"`], { windowsVerbatimArguments: true })
      : spawn('/bin/sh', ['-c', command]);
  return new Promise((resolve) => {
    let out = '';
    child.stdout.on('data', (c) => (out += c));
    child.on('close', (code) => resolve({ code, out: out.trim() }));
    child.stdin.end(JSON.stringify(payload));
  });
}

test('preview changes nothing; --apply without a location is refused', () => {
  const s = sandbox();
  try {
    const r = cli(['hooks'], s.env);
    assert.equal(r.status, 0);
    assert.match(r.stdout, /Choose where: agentguard hooks --workspace/);
    const w = cli(['hooks', '--workspace', s.workspace], s.env);
    assert.match(w.stdout, /preview — nothing will be changed/);
    assert.match(w.stdout, /will: create hooks.json with the AgentGuard PreToolUse hook/);
    assert.ok(!fs.existsSync(s.hooksFile), 'no hooks.json written by a preview');
    assert.ok(!fs.existsSync(s.agHome), 'no policy written by a preview');
    assert.equal(cli(['hooks', '--apply'], s.env).status, 2);
  } finally {
    s.cleanup();
  }
});

test('--apply: creates the policy, self-tests, writes one "agentguard" group, and the installed hook really works', async () => {
  const s = sandbox();
  try {
    const r = cli(['hooks', '--workspace', s.workspace, '--apply'], s.env);
    assert.equal(r.status, 0, r.stdout);
    assert.match(r.stdout, /✓ created policy/);
    assert.match(r.stdout, /✓ self-test: the hook command answered \{\} as expected/);
    assert.match(r.stdout, /no restart needed/);

    const hooks = JSON.parse(fs.readFileSync(s.hooksFile, 'utf8'));
    assert.deepEqual(Object.keys(hooks), ['agentguard']);
    const command = hooks.agentguard.PreToolUse[0].hooks[0].command;
    assert.equal(hooks.agentguard.PreToolUse[0].matcher, '.*');
    assert.ok(hooks.agentguard.PreToolUse[0].hooks[0].timeout > 8, 'Antigravity timeout above the hook deadline');
    assert.ok(fs.existsSync(path.join(s.agHome, 'antigravity-policy.yaml')));

    // End to end: the exact installed command, run the way Antigravity runs it.
    const denied = await runInstalledHook(command, real.readFile(path.join(s.workspace, 'old', '.aws', 'credentials')));
    assert.equal(denied.code, 0);
    assert.equal(JSON.parse(denied.out).decision, 'deny');
    const allowed = await runInstalledHook(command, real.readFile(path.join(s.workspace, 'README.md')));
    assert.deepEqual(JSON.parse(allowed.out), { decision: 'allow' });
    // The Linux build's payload (no hookEventName, no cwd) works with the installed command (Phase 6.5).
    const { linuxShape } = await import('./fixtures/antigravity-payloads.js');
    const linux = await runInstalledHook(command, linuxShape(real.readFile('.aws/credentials')));
    assert.equal(JSON.parse(linux.out).decision, 'deny', linux.out);
    const audit = fs.readFileSync(path.join(s.agHome, 'audit.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
    assert.deepEqual(audit.map((e) => e.decision), ['BLOCK', 'ALLOW', 'BLOCK'], 'decisions in the shared audit log; the self-test logged nothing');
    assert.equal(audit[2].rule, 'filesystem.deny', 'denied for the right reason, not as malformed input');

    const again = cli(['hooks', '--workspace', s.workspace, '--apply'], s.env);
    assert.match(again.stdout, /already installed/);
  } finally {
    s.cleanup();
  }
});

test('other hook groups and the file format are preserved; remove takes out only AgentGuard; backups are kept', () => {
  const s = sandbox();
  try {
    fs.mkdirSync(path.dirname(s.hooksFile), { recursive: true });
    const original = '{\r\n    "my-linter": {\r\n        "PostToolUse": [ { "matcher": "run_command", "hooks": [ { "command": "lint.cmd" } ] } ]\r\n    }\r\n}\r\n';
    fs.writeFileSync(s.hooksFile, original);
    assert.equal(cli(['hooks', '--workspace', s.workspace, '--apply'], s.env).status, 0);
    const text = fs.readFileSync(s.hooksFile, 'utf8');
    assert.ok(text.includes('\r\n') && text.includes('    "my-linter"'), 'CRLF and 4-space indent kept');
    const parsed = JSON.parse(text);
    assert.deepEqual(Object.keys(parsed), ['my-linter', 'agentguard']);
    assert.deepEqual(parsed['my-linter'], JSON.parse(original)['my-linter']);

    const preview = cli(['hooks', 'remove', '--workspace', s.workspace], s.env);
    assert.match(preview.stdout, /will: remove the "agentguard" group only/);
    assert.ok(fs.readFileSync(s.hooksFile, 'utf8').includes('agentguard'), 'preview removed nothing');

    const rm = cli(['hooks', 'remove', '--workspace', s.workspace, '--apply'], s.env);
    assert.equal(rm.status, 0);
    assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(s.hooksFile, 'utf8'))), ['my-linter']);
    const backups = fs.readdirSync(path.join(s.agHome, 'backups'));
    assert.equal(backups.length, 2, 'one backup per change');
    assert.ok(backups.some((b) => fs.readFileSync(path.join(s.agHome, 'backups', b), 'utf8') === original), 'exact original bytes backed up');
  } finally {
    s.cleanup();
  }
});

test('a foreign "agentguard" entry or an invalid hooks.json is never overwritten', () => {
  const s = sandbox();
  try {
    fs.mkdirSync(path.dirname(s.hooksFile), { recursive: true });
    for (const content of ['{"agentguard": {"PreToolUse": [{"matcher": ".*", "hooks": [{"command": "someone-else.cmd"}]}]}}', '{ not json']) {
      fs.writeFileSync(s.hooksFile, content);
      const r = cli(['hooks', '--workspace', s.workspace, '--apply'], s.env);
      assert.equal(r.status, 1, r.stdout);
      assert.match(r.stdout, /✗ Not changing/);
      assert.equal(fs.readFileSync(s.hooksFile, 'utf8'), content);
    }
  } finally {
    s.cleanup();
  }
});

test('a hook whose paths moved (stale) is detected and repaired', () => {
  const s = sandbox();
  try {
    assert.equal(cli(['hooks', '--workspace', s.workspace, '--apply'], s.env).status, 0);
    const hooks = JSON.parse(fs.readFileSync(s.hooksFile, 'utf8'));
    hooks.agentguard.PreToolUse[0].hooks[0].command = hooks.agentguard.PreToolUse[0].hooks[0].command.replace(/agentguard\.js/, 'old\\agentguard.js');
    fs.writeFileSync(s.hooksFile, JSON.stringify(hooks, null, 2));
    const status = cli(['status', '--project', s.workspace], s.env);
    assert.match(status.stdout, /installed with different paths/);
    assert.match(status.stdout, /the hook cannot start .*BLOCK every tool call/);
    const fix = cli(['hooks', '--workspace', s.workspace, '--apply'], s.env);
    assert.match(fix.stdout, /will: repair/);
    assert.match(cli(['status', '--project', s.workspace], s.env).stdout, /protected \(AgentGuard hook installed\)/);
  } finally {
    s.cleanup();
  }
});

test('a failing self-test leaves hooks.json untouched (a broken hook would block every tool call)', async () => {
  const s = sandbox();
  const out = [];
  try {
    const result = await runHooksCommand(['--workspace', s.workspace, '--apply'], {
      write: (t) => out.push(t),
      env: s.env,
      homedir: s.home,
      selfTest: async () => ({ ok: false, detail: 'exit code 1, stderr: boom' }),
    });
    assert.equal(result.test.ok, false);
    assert.match(out.join(''), /self-test failed .* hooks.json was NOT changed/);
    assert.ok(!fs.existsSync(s.hooksFile));
  } finally {
    process.exitCode = 0;
    s.cleanup();
  }
});

test('--global installs into ~/.gemini/config/hooks.json; status warns when global and workspace both have it', () => {
  const s = sandbox();
  try {
    assert.equal(cli(['hooks', '--global', '--apply'], s.env).status, 0);
    const globalFile = path.join(s.home, '.gemini', 'config', 'hooks.json');
    assert.equal(readHooksState(globalFile, null).state, 'stale', 'our group, present');
    const both = cli(['hooks', '--workspace', s.workspace], s.env);
    assert.match(both.stdout, /also has the AgentGuard hook: every tool call would be checked, and logged, twice/);
    cli(['hooks', '--workspace', s.workspace, '--apply'], s.env);
    assert.match(cli(['status', '--project', s.workspace], s.env).stdout, /installed globally AND in this workspace/);
  } finally {
    s.cleanup();
  }
});

test('status reports the last hook decision and tools that have no rule', async () => {
  const s = sandbox();
  try {
    cli(['hooks', '--workspace', s.workspace, '--apply'], s.env);
    const command = JSON.parse(fs.readFileSync(s.hooksFile, 'utf8')).agentguard.PreToolUse[0].hooks[0].command;
    await runInstalledHook(command, real.searchMarketplace());
    await runInstalledHook(command, { ...real.sendMessage(), toolCall: { name: 'swarm', args: {} } });
    const status = cli(['status', '--project', s.workspace], s.env).stdout;
    assert.match(status, /last hook decision: \d{4}-/);
    assert.match(status, /tools without a rule \(allowed with WARN\): swarm/);
  } finally {
    s.cleanup();
  }
});

test('the installed hook stays silent on stderr even when Node would warn (NO_COLOR + FORCE_COLOR, found on Linux)', async () => {
  const s = sandbox();
  try {
    assert.equal(cli(['hooks', '--workspace', s.workspace, '--apply'], s.env).status, 0);
    const command = JSON.parse(fs.readFileSync(s.hooksFile, 'utf8')).agentguard.PreToolUse[0].hooks[0].command;
    assert.match(command, /--no-warnings/);
    const env = { ...s.env, NO_COLOR: '1', FORCE_COLOR: '1' };
    const child =
      process.platform === 'win32'
        ? spawn('cmd.exe', ['/s', '/c', `"${command}"`], { windowsVerbatimArguments: true, env })
        : spawn('/bin/sh', ['-c', command], { env });
    let out = '';
    let err = '';
    child.stdout.on('data', (c) => (out += c));
    child.stderr.on('data', (c) => (err += c));
    child.stdin.end(JSON.stringify(real.readFile(path.join(s.workspace, 'README.md'))));
    const code = await new Promise((r) => child.on('close', r));
    assert.equal(code, 0);
    assert.deepEqual(JSON.parse(out.trim()), { decision: 'allow' });
    assert.equal(err, '', 'nothing for Antigravity to show the model');
  } finally {
    s.cleanup();
  }
});

test('status warns loudly when the hook keeps rejecting Antigravity\'s input (it then blocks every tool call)', async () => {
  const s = sandbox();
  try {
    fs.mkdirSync(s.agHome, { recursive: true });
    const bad = (t) => ({ id: t, sessionId: 'c', source: 'antigravity-hook', timestamp: `2026-11-23T21:08:0${t}Z`, decision: 'BLOCK', rule: 'malformed-hook-input', reason: 'Hook input rejected: the hook input has no hookEventName.', metadata: { payloadKeys: ['conversationId', 'toolCall'] } });
    fs.writeFileSync(path.join(s.agHome, 'audit.jsonl'), [1, 2, 3].map((t) => JSON.stringify(bad(t))).join('\n') + '\n');
    cli(['hooks', '--workspace', s.workspace, '--apply'], s.env);
    const status = cli(['status', '--project', s.workspace], s.env).stdout;
    assert.match(status, /all rejected Antigravity's input .* blocking every tool call/);
    assert.match(status, /fields received: conversationId, toolCall/);
  } finally {
    s.cleanup();
  }
});

test('the hook command refuses paths cmd.exe cannot quote safely', () => {
  assert.throws(() => buildHookCommand({ policyPath: 'C:\\a%PATH%\\p.yaml', logPath: 'l' }), /" or %/);
  assert.throws(() => buildHookCommand({ policyPath: 'C:\\a"b\\p.yaml', logPath: 'l' }), /" or %/);
});

test('drift guard: the Antigravity policy is the shipped default plus only its documented differences', () => {
  const def = yaml.load(fs.readFileSync(path.join(root, 'policy', 'default-policy.yaml'), 'utf8'));
  const ag = yaml.load(fs.readFileSync(path.join(root, 'policy', 'antigravity-policy.yaml'), 'utf8'));
  for (const section of ['mcp', 'network', 'secrets', 'mcp_response_inspection']) assert.deepEqual(ag[section], def[section], section);
  const { deny: agDeny, ...agFs } = ag.filesystem;
  const { deny: defDeny, ...defFs } = def.filesystem;
  assert.deepEqual(agFs, defFs, 'filesystem apart from deny');
  for (const d of defDeny) assert.ok(agDeny.includes(d), `antigravity policy keeps default deny ${d}`);
  const { allowed, deny, unlisted, ...agShell } = ag.shell;
  const { allowed: a2, deny: d2, unlisted: u2, ...defShell } = def.shell;
  assert.deepEqual(agShell, defShell, 'shell apart from allowed/deny/unlisted');
  for (const d of d2) assert.ok(deny.includes(d), `antigravity policy keeps default shell deny ${d}`);
  assert.equal(unlisted, 'warn');
});

test('self-protection: with the Antigravity policy, the agent cannot edit the hook or AgentGuard\'s own files', () => {
  const engine = new PolicyEngine(applyDefaults(yaml.load(fs.readFileSync(path.join(root, 'policy', 'antigravity-policy.yaml'), 'utf8'))));
  const home = os.homedir();
  const targets = [
    'C:\\work\\demo\\.agents\\hooks.json',
    path.join(home, '.gemini', 'config', 'hooks.json'),
    path.join(home, '.gemini', 'config', 'mcp_config.json'),
    path.join(home, '.agentguard', 'antigravity-policy.yaml'),
    path.join(home, '.agentguard', 'audit.jsonl'),
  ];
  for (const t of targets) {
    for (const p of [real.writeFile(t, '{}'), real.editFile(t), real.readFile(t)]) {
      const { output } = handleHookInput(JSON.stringify(p), { engine, logger: { log() {} }, platform: 'linux' });
      assert.equal(output.decision, 'deny', `${p.toolCall.name} ${t}`);
    }
  }
  // The agent's tool-schema cache (read before every MCP call) stays readable.
  const schema = real.readFile(path.join(home, '.gemini', 'antigravity', 'mcp', 'burpsuite', 'base64_encode.json'));
  assert.equal(handleHookInput(JSON.stringify(schema), { engine, logger: { log() {} } }).output.decision, 'allow');
});

test('self-protection through the terminal (real PowerShell parser)', { skip: process.platform !== 'win32' && 'needs Windows PowerShell' }, () => {
  const engine = new PolicyEngine(applyDefaults(yaml.load(fs.readFileSync(path.join(root, 'policy', 'antigravity-policy.yaml'), 'utf8'))));
  for (const line of [
    "Set-Content .agents\\hooks.json '{}'",
    'Remove-Item .agents\\hooks.json',
    // Found by this test: a redirection after an EXPRESSION was not seen.
    "'{}' > .agents\\hooks.json",
    "'{}' | Out-File .agents\\hooks.json",
    'Copy-Item x.json $HOME\\.gemini\\config\\hooks.json',
    // ${C:\...} writes a file through variable syntax, with no command at all.
    "${C:\\work\\demo\\.agents\\hooks.json} = '{}'",
  ]) {
    const { output } = handleHookInput(JSON.stringify(real.runCommand(line)), { engine, logger: { log() {} } });
    assert.equal(output.decision, 'deny', line);
  }
});
