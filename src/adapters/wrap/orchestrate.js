import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { clientConfigs } from '../discovery/client-configs.js';
import { homePaths } from '../../core/agentguard-home.js';
import { readConfigFile, serializeConfig, serverTable, serverTableKey, writeConfigSafely, ConfigError } from './config-file.js';
import { planServers, classifyEntry } from './plan.js';
import { ensurePolicy } from './policy-file.js';

const SCRIPT_PATH = fileURLToPath(new URL('../../../bin/agentguard.js', import.meta.url));

/** Everything the plan needs to know about THIS install and machine. */
export function buildContext({ env = process.env, homedir = os.homedir(), cwd = process.cwd(), platform = process.platform } = {}) {
  const paths = homePaths({ env, homedir });
  return {
    nodePath: process.execPath,
    scriptPath: SCRIPT_PATH,
    policyPath: paths.policy,
    logPath: paths.audit,
    paths,
    env,
    homedir,
    cwd,
    platform,
  };
}

/**
 * Which config files to look at. Explicit `--config` files win over
 * discovery (so a test or an unlisted app never touches anything else);
 * `clientIds` narrows the known list.
 */
export function selectTargets(ctx, { clientIds = [], configFiles = [] } = {}) {
  const custom = configFiles.map((f) => ({
    id: 'custom',
    label: path.basename(f),
    path: path.resolve(ctx.cwd, f),
    wrappable: true,
  }));
  if (configFiles.length > 0 && clientIds.length === 0) return custom;

  const known = clientConfigs({ cwd: ctx.cwd, platform: ctx.platform, homedir: ctx.homedir, env: ctx.env });
  const picked = clientIds.length ? known.filter((c) => clientIds.includes(c.id)) : known;
  return [...picked, ...custom];
}

/** Reads + plans every target. Pure of side effects (read-only). */
export function planAll(mode, targets, ctx) {
  return targets.map((client) => {
    const result = { client, file: client.path, status: 'ready', error: null, info: null, servers: [] };
    try {
      result.info = readConfigFile(client.path);
    } catch (err) {
      if (!(err instanceof ConfigError)) throw err;
      result.status = err.kind === 'absent' ? 'absent' : 'unparseable';
      result.error = err.message;
      return result;
    }

    result.servers = planServers(serverTable(result.info), mode, ctx);
    if (result.servers.length === 0) result.status = 'no-servers';
    if (!client.wrappable) {
      result.status = 'unsupported';
      for (const s of result.servers) s.action = 'skip';
    }
    return result;
  });
}

export const hasChanges = (plan) => plan.some((t) => t.servers.some((s) => s.action !== 'skip'));

/**
 * True when some already-wrapped server points at the policy file but that
 * file is gone. Such a server cannot start, and `wrap --apply` must be able to
 * repair it even though no client config needs changing.
 */
export function policyMissing(plan, ctx) {
  return !fs.existsSync(ctx.paths.policy) && plan.some((t) => t.client.wrappable && t.servers.some((s) => s.state === 'wrapped'));
}

/**
 * Applies a plan. For wrap: the policy is ensured FIRST (a wrapped entry
 * with no policy file would not start). Each config file is written
 * independently and atomically; a failure on one is reported and does not
 * stop the others.
 */
export function applyPlan(mode, plan, ctx) {
  const outcome = { policy: null, files: [] };

  if (mode === 'wrap' && (hasChanges(plan) || policyMissing(plan, ctx))) {
    const names = plan.flatMap((t) =>
      t.client.wrappable ? t.servers.filter((s) => s.action !== 'skip' || s.state === 'wrapped').map((s) => s.name) : []
    );
    outcome.policy = ensurePolicy({ policyPath: ctx.paths.policy, names, backupDir: ctx.paths.backups });
    fs.mkdirSync(path.dirname(ctx.paths.audit), { recursive: true });
  }

  for (const target of plan) {
    const changed = target.servers.filter((s) => s.action !== 'skip');
    if (changed.length === 0) continue;

    const key = serverTableKey(target.info);
    const table = { ...serverTable(target.info) };
    for (const s of changed) table[s.name] = s.after;
    const next = { ...target.info.parsed, [key]: table };

    try {
      const backup = writeConfigSafely(target.info, serializeConfig(target.info, next), { backupDir: ctx.paths.backups });
      outcome.files.push({ file: target.file, client: target.client, ok: true, backup, changed: changed.map((s) => `${s.action} ${s.name}`) });
    } catch (err) {
      outcome.files.push({ file: target.file, client: target.client, ok: false, error: err.message });
    }
  }
  return outcome;
}

/** Wrapped-entry health for `status`: which wrapped entries would fail to start. */
export function wrapperProblems(plan, ctx) {
  const problems = [];
  for (const t of plan) {
    for (const s of t.servers) {
      const cls = classifyEntry(s.name, s.before, ctx);
      if (cls.state === 'stale') {
        problems.push(`${t.client.label} / ${s.name}: wrapper points at a different install or path. Run: agentguard wrap --apply`);
      }
      if (cls.state === 'wrapped' || cls.state === 'stale') {
        // Check the files THIS entry actually depends on (its own policy path,
        // not necessarily ~/.agentguard/policy.yaml): a missing one means the
        // server fails to start.
        const args = s.before.args;
        const policyIdx = args.indexOf('--policy');
        const needed = [s.before.command, args[0], policyIdx !== -1 ? args[policyIdx + 1] : null];
        const missing = needed.filter((p) => p && path.isAbsolute(p) && !fs.existsSync(p));
        if (missing.length) problems.push(`${t.client.label} / ${s.name}: will fail to start, missing file ${missing.join(', ')}. Run: agentguard wrap --apply`);
      }
    }
  }
  return problems;
}
