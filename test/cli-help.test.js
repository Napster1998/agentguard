// `agentguard --help` and every subcommand's --help, run as real subprocesses.
// Help must print to stdout and exit 0, must NOT run the command it describes,
// and must not drift from the flags the commands really accept.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { COMMANDS, USAGE, commandHelp, wantsHelp } from '../src/cli/help.js';
import { clientConfigs } from '../src/adapters/discovery/client-configs.js';

const execFileAsync = promisify(execFile);
const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'agentguard.js');

// If help ever fails to intercept and a command really runs, it runs against
// an empty throwaway home, never the developer's real one.
function sandboxEnv() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'ag-help-'));
  return { home, env: { ...process.env, HOME: home, USERPROFILE: home, APPDATA: path.join(home, 'AppData'), AGENTGUARD_HOME: path.join(home, '.agentguard') } };
}

async function run(args, env) {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [CLI, ...args], { env, timeout: 20000 });
    return { code: 0, stdout, stderr };
  } catch (e) {
    return { code: e.code, stdout: e.stdout || '', stderr: e.stderr || '' };
  }
}

test('top level: no args, --help, -h, help and --usage all print the same help to stdout and exit 0', async () => {
  const { home, env } = sandboxEnv();
  try {
    const outputs = [];
    for (const args of [[], ['--help'], ['-h'], ['help'], ['--usage']]) {
      const r = await run(args, env);
      assert.equal(r.code, 0, `agentguard ${args.join(' ')}`);
      assert.equal(r.stderr, '', `agentguard ${args.join(' ')} wrote to stderr`);
      assert.match(r.stdout, /Usage: agentguard <command> \[options\]/);
      assert.match(r.stdout, /Typical flow/);
      for (const c of COMMANDS) assert.ok(r.stdout.includes(c.name), `${c.name} listed`);
      outputs.push(r.stdout);
    }
    assert.ok(outputs.every((o) => o === outputs[0]), 'every spelling shows the identical help');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('every command: --help, -h and `help <command>` print that command\'s usage, exit 0, and do NOT run the command', async () => {
  const { home, env } = sandboxEnv();
  try {
    for (const { name } of COMMANDS) {
      const expected = commandHelp(name);
      for (const args of [[name, '--help'], [name, '-h'], ['help', name]]) {
        const r = await run(args, env);
        assert.equal(r.code, 0, `agentguard ${args.join(' ')}`);
        assert.equal(r.stdout, expected, `agentguard ${args.join(' ')}`);
        assert.ok(r.stdout.startsWith(`Usage: ${USAGE[name]}`));
        assert.equal(r.stderr, '');
      }
    }
    // status / scan / events are read-only but used to RUN when given --help
    for (const [cmd, marker] of [['status', 'AgentGuard status'], ['scan', 'AI Agent Security Scan'], ['events', 'Session ']]) {
      assert.ok(!(await run([cmd, '--help'], env)).stdout.includes(marker), `${cmd} --help must not run ${cmd}`);
    }
    assert.equal(fs.existsSync(env.AGENTGUARD_HOME), false, 'asking for help created no state');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('--help after a standalone `--` belongs to the wrapped command, not to AgentGuard', () => {
  assert.equal(wantsHelp(['--policy', 'p', '--', 'npx', '--help']), false);
  assert.equal(wantsHelp(['--', '-h']), false);
  assert.equal(wantsHelp(['--policy', 'p', '-h']), true);
  assert.equal(wantsHelp(['--apply', '--help']), true);
  assert.equal(wantsHelp([]), false);
});

test('an unknown command is an error: nothing on stdout, a pointer to --help on stderr, exit 2', async () => {
  const { home, env } = sandboxEnv();
  try {
    for (const args of [['bogus'], ['help', 'bogus']]) {
      const r = await run(args, env);
      assert.equal(r.code, 2, args.join(' '));
      assert.equal(r.stdout, '');
      assert.match(r.stderr, /unknown command "bogus"/);
      assert.match(r.stderr, /agentguard --help/);
    }
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('a usage ERROR (gateway/exec with no `--`) still exits 2 on stderr and points at --help', async () => {
  const { home, env } = sandboxEnv();
  try {
    for (const cmd of ['gateway', 'exec']) {
      const r = await run([cmd, '--policy', 'p.yaml'], env);
      assert.equal(r.code, 2, cmd);
      assert.equal(r.stdout, '');
      assert.match(r.stderr, new RegExp(`Usage: agentguard ${cmd} --policy`));
      assert.match(r.stderr, new RegExp(`agentguard ${cmd} --help`));
    }
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('drift guard: each command\'s help mentions every flag it really accepts', () => {
  const flags = {
    wrap: ['--apply', '--client', '--config', '--project'],
    unwrap: ['--apply', '--client', '--config', '--project'],
    status: ['--project'],
    events: ['--log', '--session', '--risk', '--blocked'],
    scan: ['--policy', '--json'],
    gateway: ['--policy', '--log', '--server-name'],
    exec: ['--policy', '--log'],
  };
  assert.deepEqual(Object.keys(flags).sort(), COMMANDS.map((c) => c.name).sort(), 'every command is covered here');
  for (const [name, list] of Object.entries(flags)) {
    for (const f of list) assert.ok(commandHelp(name).includes(f), `${name} help is missing ${f}`);
  }
});

test('drift guard: wrap help lists exactly the client ids wrap really supports', () => {
  const supported = clientConfigs().filter((c) => c.wrappable).map((c) => c.id);
  for (const id of supported) assert.ok(commandHelp('wrap').includes(id), `${id} missing from wrap help`);
  for (const c of clientConfigs().filter((x) => !x.wrappable)) {
    assert.ok(!commandHelp('wrap').split('\n').some((l) => l.includes('--client') && l.includes(c.id)), `${c.id} is not wrappable and must not be offered`);
  }
});

test('help is honest about the one thing that surprised us: --risk is an exact match, not "at least"', () => {
  assert.match(commandHelp('events'), /exactly this risk/);
});
