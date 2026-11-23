import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { bold } from '../core/colors.js';
import { homePaths } from '../core/agentguard-home.js';
import { commandHelp } from './help.js';
import {
  hooksFileFor,
  buildHookCommand,
  readHooksState,
  selfTestHook,
  ensureAntigravityPolicy,
  writeHooksGroup,
  removeHooksGroup,
} from '../adapters/antigravity/hooks-config.js';

const RULE = '─'.repeat(40);

function parseArgs(argv) {
  const opts = { mode: 'install', apply: false, workspace: null, global: false, error: null };
  const args = [...argv];
  if (args[0] === 'remove') {
    opts.mode = 'remove';
    args.shift();
  }
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--apply') opts.apply = true;
    else if (a === '--global') opts.global = true;
    else if (a === '--workspace') {
      opts.workspace = args[++i];
      if (!opts.workspace) opts.error = '--workspace needs a folder';
    } else opts.error = `unknown option "${a}"`;
  }
  if (opts.global && opts.workspace) opts.error = 'choose --workspace <dir> OR --global, not both';
  return opts;
}

const STATE_TEXT = {
  absent: 'no hooks.json yet',
  none: 'hooks.json exists, AgentGuard not installed',
  installed: 'AgentGuard installed',
  stale: 'AgentGuard installed, but with different paths (needs repair)',
  disabled: 'AgentGuard installed but disabled ("enabled": false)',
  foreign: 'has an "agentguard" entry that is NOT AgentGuard\'s hook (left alone)',
  unparseable: 'not valid JSON (left alone)',
};

/** Both places Antigravity reads hooks from, for this machine and folder. */
export function hookLocations({ workspace, homedir = os.homedir(), command }) {
  return [
    { label: 'Global (every Antigravity workspace)', ...readHooksState(hooksFileFor({ global: true, homedir }), command) },
    { label: `Workspace ${path.resolve(workspace)}`, ...readHooksState(hooksFileFor({ workspace }), command) },
  ];
}

/**
 * `agentguard hooks [--workspace <dir> | --global] [--apply]`
 * `agentguard hooks remove [--workspace <dir> | --global] [--apply]`
 * Preview by default, like wrap.
 */
export async function runHooksCommand(argv, deps = {}) {
  const write = deps.write || ((s) => process.stdout.write(s));
  const env = deps.env || process.env;
  const homedir = deps.homedir || os.homedir();
  const opts = parseArgs(argv);
  if (opts.error) {
    write(`agentguard hooks: ${opts.error}\n${commandHelp('hooks')}`);
    process.exitCode = 2;
    return null;
  }

  const paths = homePaths({ env, homedir });
  let command;
  try {
    command = buildHookCommand({ policyPath: paths.antigravityPolicy, logPath: paths.audit });
  } catch (err) {
    write(`✗ ${err.message}\n`);
    process.exitCode = 1;
    return null;
  }

  write(`${bold(`AgentGuard hooks${opts.mode === 'remove' ? ' remove' : ''}`)}${opts.apply ? '' : '  (preview — nothing will be changed)'}\n${RULE}\n\n`);

  const locations = hookLocations({ workspace: opts.workspace || process.cwd(), homedir, command });
  if (!opts.global && !opts.workspace) {
    for (const l of locations) write(`${l.label}\n  ${l.file}\n  ${STATE_TEXT[l.state]}\n\n`);
    write('Choose where: agentguard hooks --workspace <folder>   (only that workspace; tested)\n');
    write('          or: agentguard hooks --global               (every Antigravity workspace)\n');
    if (opts.apply) process.exitCode = 2;
    return { locations };
  }

  const target = opts.global ? locations[0] : locations[1];
  const other = opts.global ? locations[1] : locations[0];
  write(`${target.label}\n  ${target.file}\n  now: ${STATE_TEXT[target.state]}\n`);

  if (opts.mode === 'remove') return remove(target, { write, opts, paths });
  return install(target, other, { write, opts, paths, command, deps });
}

async function install(target, other, { write, opts, paths, command, deps }) {
  if (target.state === 'foreign' || target.state === 'unparseable') {
    write(`\n✗ Not changing ${target.file}: ${STATE_TEXT[target.state]}.\n`);
    if (target.error) write(`  ${target.error}\n`);
    process.exitCode = 1;
    return { target };
  }
  if (target.state === 'installed') {
    write('\nNothing to do: AgentGuard is already installed here, with the current paths.\n');
    return { target };
  }

  const action = { absent: 'create hooks.json with', none: 'add', stale: 'repair', disabled: 're-enable' }[target.state];
  write(`  will: ${action} the AgentGuard PreToolUse hook\n\n`);
  const policyExists = fs.existsSync(paths.antigravityPolicy);
  write(`Policy: ${paths.antigravityPolicy}\n  ${policyExists ? 'exists, kept as it is' : 'will be created from policy/antigravity-policy.yaml (coding-agent profile)'}\n`);
  if (policyExists && !fs.readFileSync(paths.antigravityPolicy, 'utf8').includes('.agents/hooks.json')) {
    write('  ⚠ it does not deny writes to hooks.json: an agent could switch AgentGuard off.\n    Compare it with policy/antigravity-policy.yaml (filesystem.deny, "Self-protection").\n');
  }
  write(`Audit log: ${paths.audit}\nHook command: ${command}\n`);
  if (['installed', 'stale', 'disabled'].includes(other.state)) {
    write(`\n⚠ ${other.label} also has the AgentGuard hook: every tool call would be checked, and logged, twice.\n`);
  }

  if (!opts.apply) {
    write(`\nNothing was changed. To apply: agentguard hooks ${opts.global ? '--global' : `--workspace "${opts.workspace}"`} --apply\n`);
    return { target };
  }

  const policy = ensureAntigravityPolicy(paths.antigravityPolicy);
  if (policy.created) write(`\n✓ created policy ${paths.antigravityPolicy}\n`);
  fs.mkdirSync(path.dirname(paths.audit), { recursive: true });

  // Antigravity BLOCKS every tool call if the hook fails, so never write a hook
  // that has not just answered correctly, run exactly the way Antigravity runs it.
  const test = await (deps.selfTest || selfTestHook)(command);
  if (!test.ok) {
    write(`✗ self-test failed (${test.detail}); hooks.json was NOT changed.\n  Installing a failing hook would make Antigravity block every tool call.\n`);
    process.exitCode = 1;
    return { target, test };
  }
  write(`✓ self-test: the hook command ${test.detail}\n`);

  try {
    const result = writeHooksGroup(target, command, { backupDir: paths.backups });
    write(`✓ ${result.created ? 'created' : 'updated'} ${result.file}\n`);
    if (result.backup) write(`    backup: ${result.backup}\n`);
  } catch (err) {
    write(`✗ ${err.message}\n`);
    process.exitCode = 1;
    return { target };
  }
  write('\nIt takes effect on the next tool call (Antigravity re-reads hooks.json; no restart needed).\n');
  write(`Check it: agentguard status      See activity: agentguard events\nUndo it:  agentguard hooks remove ${opts.global ? '--global' : `--workspace "${opts.workspace}"`} --apply\n`);
  return { target, test };
}

function remove(target, { write, opts, paths }) {
  if (!['installed', 'stale', 'disabled'].includes(target.state)) {
    write('\nNothing to remove.\n');
    return { target };
  }
  write('  will: remove the "agentguard" group only (other hooks are kept)\n');
  if (!opts.apply) {
    write(`\nNothing was changed. To apply: agentguard hooks remove ${opts.global ? '--global' : `--workspace "${opts.workspace}"`} --apply\n`);
    return { target };
  }
  try {
    const result = removeHooksGroup(target, { backupDir: paths.backups });
    write(`\n✓ removed the AgentGuard hook from ${result.file}\n    backup: ${result.backup}\nIt takes effect on the next tool call. Your policy and audit log are kept.\n`);
  } catch (err) {
    write(`\n✗ ${err.message}\n`);
    process.exitCode = 1;
  }
  return { target };
}
