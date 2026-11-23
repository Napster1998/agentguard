import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { readConfigFile, serializeConfig, writeConfigSafely, ConfigError } from '../wrap/config-file.js';

/**
 * Installing / removing AgentGuard as an Antigravity PreToolUse hook.
 *
 * hooks.json is a map of NAMED hook groups (Antigravity docs, confirmed in the
 * Phase 6 spike), so AgentGuard owns exactly one key, "agentguard", and never
 * touches the others. Facts from the spike this relies on:
 *  - a workspace's `.agents/hooks.json` is loaded for that workspace, and the
 *    file is re-read before EVERY tool call: install and removal are instant;
 *  - on Windows the command runs as `cmd /s /c "<command>"`, so every path is
 *    double-quoted (proven to work with C:\Program Files\...);
 *  - a hook that fails (exit != 0, bad output, timeout) BLOCKS the call. A
 *    broken install would therefore block every tool call, which is why the
 *    exact command is self-tested before hooks.json is written.
 */

export const GROUP = 'agentguard';
const SCRIPT_PATH = fileURLToPath(new URL('../../../bin/agentguard.js', import.meta.url));
export const POLICY_TEMPLATE = fileURLToPath(new URL('../../../policy/antigravity-policy.yaml', import.meta.url));
const HOOK_TIMEOUT_S = 15; // above the hook's own 8 s deadline

/** Where a hooks.json lives: a workspace's, or the global one. */
export function hooksFileFor({ workspace = null, global = false, homedir = os.homedir() }) {
  if (global) return path.join(homedir, '.gemini', 'config', 'hooks.json');
  return path.join(path.resolve(workspace), '.agents', 'hooks.json');
}

/** cmd.exe expands %VAR% even inside quotes, and a " would end the quoting. */
const UNSAFE_PATH_CHARS = /["%\r\n]/;

export function buildHookCommand({ nodePath = process.execPath, scriptPath = SCRIPT_PATH, policyPath, logPath }) {
  for (const p of [nodePath, scriptPath, policyPath, logPath]) {
    if (UNSAFE_PATH_CHARS.test(p)) throw new Error(`cannot install the hook: the path ${p} contains a " or %, which the hook command cannot quote safely`);
  }
  return `"${nodePath}" "${scriptPath}" hook antigravity --policy "${policyPath}" --log "${logPath}"`;
}

export function buildGroup(command) {
  return { enabled: true, PreToolUse: [{ matcher: '.*', hooks: [{ type: 'command', command, timeout: HOOK_TIMEOUT_S }] }] };
}

/** The command string inside an existing group, if it is shaped like ours. */
function groupCommand(group) {
  return group?.PreToolUse?.[0]?.hooks?.[0]?.command;
}

/** Is this group AgentGuard's (whatever its paths)? Structural, like wrapped MCP entries. */
export function isAgentGuardGroup(group) {
  const cmd = groupCommand(group);
  return typeof cmd === 'string' && /agentguard\.js"?\s+hook\s+antigravity\b/i.test(cmd);
}

/**
 * State of one hooks.json for AgentGuard:
 *   absent      no file
 *   unparseable not valid JSON / not an object (left untouched)
 *   none        file exists, no "agentguard" group
 *   installed   our group, with exactly the command this install would write
 *   stale       our group, different paths (moved repo, new node, other policy)
 *   disabled    our group with "enabled": false
 *   foreign     an "agentguard" key that is NOT ours (never overwritten)
 */
export function readHooksState(file, expectedCommand) {
  let info;
  try {
    info = readConfigFile(file);
  } catch (err) {
    if (err instanceof ConfigError && err.kind === 'absent') return { file, state: 'absent', info: null };
    return { file, state: 'unparseable', info: null, error: err.message };
  }
  const group = info.parsed[GROUP];
  if (group === undefined) return { file, state: 'none', info, otherGroups: Object.keys(info.parsed) };
  if (!isAgentGuardGroup(group)) return { file, state: 'foreign', info };
  const command = groupCommand(group);
  if (group.enabled === false) return { file, state: 'disabled', info, command };
  return { file, state: command === expectedCommand ? 'installed' : 'stale', info, command };
}

/**
 * Runs the hook command exactly the way Antigravity does (Windows:
 * `cmd /s /c "<command>"`; elsewhere `sh -c`), feeding it a SessionStart event.
 * A working hook loads its policy and answers `{}` with exit 0 and no stderr.
 * Anything else means installing it would make Antigravity block every call.
 *
 * @returns {Promise<{ok: boolean, detail: string}>}
 */
export function selfTestHook(command, { cwd = os.tmpdir(), timeoutMs = 20000, platform = process.platform } = {}) {
  const payload = JSON.stringify({ hookEventName: 'SessionStart', conversationId: 'agentguard-self-test', cwd, workspacePaths: [cwd] });
  return new Promise((resolve) => {
    const child =
      platform === 'win32'
        ? spawn('cmd.exe', ['/s', '/c', `"${command}"`], { windowsVerbatimArguments: true, cwd, windowsHide: true })
        : spawn('/bin/sh', ['-c', command], { cwd });
    let out = '';
    let err = '';
    const timer = setTimeout(() => {
      child.kill();
      resolve({ ok: false, detail: `no answer within ${timeoutMs / 1000} s` });
    }, timeoutMs);
    child.stdout.on('data', (c) => (out += c));
    child.stderr.on('data', (c) => (err += c));
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ ok: false, detail: `could not start: ${e.message}` });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      const answer = out.trim();
      if (code === 0 && answer === '{}' && err === '') return resolve({ ok: true, detail: 'answered {} as expected' });
      let why = `exit code ${code}`;
      if (answer && answer !== '{}') why += `, answered ${answer.slice(0, 200)}`;
      if (err) why += `, stderr: ${err.trim().split(/\r?\n/)[0].slice(0, 200)}`;
      resolve({ ok: false, detail: why });
    });
    child.stdin.end(payload);
  });
}

/** First run: copy the Antigravity policy template. Never overwrites an existing policy. */
export function ensureAntigravityPolicy(policyPath, { template = POLICY_TEMPLATE } = {}) {
  if (fs.existsSync(policyPath)) return { created: false };
  fs.mkdirSync(path.dirname(policyPath), { recursive: true });
  fs.writeFileSync(policyPath, fs.readFileSync(template, 'utf8'));
  return { created: true };
}

/**
 * Adds (or repairs) the "agentguard" group. Existing file: backup + atomic
 * write that refuses if the file changed meanwhile (config-file.js). New file:
 * created atomically, refusing if one appeared meanwhile.
 * @returns {{file: string, backup: string|null, created: boolean}}
 */
export function writeHooksGroup(stateInfo, command, { backupDir }) {
  const { file, info } = stateInfo;
  if (!info) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.agentguard-tmp-${process.pid}`;
    fs.writeFileSync(tmp, JSON.stringify({ [GROUP]: buildGroup(command) }, null, 2) + '\n');
    if (fs.existsSync(file)) {
      fs.unlinkSync(tmp);
      throw new Error(`${file} appeared while planning; nothing was written (re-run)`);
    }
    fs.renameSync(tmp, file);
    return { file, backup: null, created: true };
  }
  const next = { ...info.parsed, [GROUP]: buildGroup(command) };
  const backup = writeConfigSafely(info, serializeConfig(info, next), { backupDir });
  return { file, backup, created: false };
}

/** Removes only the "agentguard" group (backup first). */
export function removeHooksGroup(stateInfo, { backupDir }) {
  const { info } = stateInfo;
  const next = { ...info.parsed };
  delete next[GROUP];
  const backup = writeConfigSafely(info, serializeConfig(info, next), { backupDir });
  return { file: stateInfo.file, backup };
}
