import path from 'node:path';

import { bold } from '../core/colors.js';
import { listProcesses as defaultListProcesses } from '../adapters/host/process-list.js';
import { buildContext, selectTargets, planAll, applyPlan, hasChanges } from '../adapters/wrap/orchestrate.js';

const RULE = '─'.repeat(40);

function usage(mode) {
  return (
    `Usage: agentguard ${mode} [--apply] [--client <id>]... [--config <file>]... [--project <dir>]\n` +
    `  (no --apply)    preview only: shows exactly what would change, changes nothing\n` +
    `  --apply         ${mode === 'wrap' ? 'back up, then wrap every supported MCP server' : 'restore every wrapped MCP server to its original command'}\n` +
    `  --client <id>   only this client: claude-desktop, antigravity, claude-code-project\n` +
    `  --config <file> a JSON file with an "mcpServers" section for an app not on the list\n` +
    `                  (when given, ONLY these files are considered)\n` +
    `  --project <dir> look for a project .mcp.json in <dir> instead of the current folder\n`
  );
}

function parseArgs(argv) {
  const opts = { apply: false, clientIds: [], configFiles: [], project: null, help: false, error: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--apply') opts.apply = true;
    else if (a === '--client') opts.clientIds.push(argv[++i]);
    else if (a === '--config') opts.configFiles.push(argv[++i]);
    else if (a === '--project') opts.project = argv[++i];
    else if (a === '-h' || a === '--help') opts.help = true;
    else opts.error = `unknown option "${a}"`;
  }
  if ([...opts.clientIds, ...opts.configFiles, opts.project === null ? 'x' : opts.project].some((v) => v === undefined)) {
    opts.error = opts.error || 'an option is missing its value';
  }
  return opts;
}

/** One-line, secret-free description of a server entry: never prints args or env values. */
function describe(def) {
  if (!def || typeof def !== 'object') return '(not a valid entry)';
  if (def.url) return `remote: ${String(def.url).replace(/\?.*$/, '')}`;
  const cmd = typeof def.command === 'string' ? path.basename(def.command.replace(/\\/g, '/')) : '?';
  const n = Array.isArray(def.args) ? def.args.length : 0;
  return `${cmd}${n ? `, ${n} arg${n === 1 ? '' : 's'}` : ''}`;
}

const LABEL_WIDTH = 17;
const row = (mark, label, name, detail = '') => `  ${mark} ${label.padEnd(LABEL_WIDTH)} ${name.padEnd(18)} ${detail}`.trimEnd();

const ACTION_LABEL = {
  wrap: { mark: '⚠', text: 'will wrap' },
  repair: { mark: '⚠', text: 'will repair' },
  unwrap: { mark: '⚠', text: 'will unwrap' },
};

function formatPlan(plan) {
  const lines = [];
  for (const t of plan) {
    lines.push(bold(t.client.label));
    if (t.status === 'absent') {
      lines.push('  · not found on this machine');
      continue;
    }
    lines.push(`  ${t.file}`);
    if (t.status === 'unparseable') {
      lines.push(`  ⚠ skipped: ${t.error}`);
      continue;
    }
    if (t.status === 'unsupported') {
      lines.push(`  · ${t.servers.length} server(s) found, not managed: ${t.client.reason}`);
      continue;
    }
    if (t.status === 'no-servers') {
      lines.push('  · no MCP servers configured');
      continue;
    }
    for (const s of t.servers) {
      const a = ACTION_LABEL[s.action];
      if (a) lines.push(row(a.mark, a.text, s.name, describe(s.before)));
      else if (s.state === 'wrapped') lines.push(row('✓', 'already wrapped', s.name));
      else if (s.state === 'remote' || s.state === 'invalid') lines.push(row('·', 'skipped', s.name, s.reason));
      else lines.push(row('·', 'unchanged', s.name));
    }
  }
  return lines.join('\n');
}

/**
 * `agentguard wrap` and `agentguard unwrap`. Preview by default; --apply
 * makes changes (after backing up each file).
 */
export async function runWrapCommand(argv, mode = 'wrap', deps = {}) {
  const write = deps.write || ((s) => process.stdout.write(s));
  const opts = parseArgs(argv);
  if (opts.help || opts.error) {
    if (opts.error) write(`agentguard ${mode}: ${opts.error}\n`);
    write(usage(mode));
    process.exitCode = opts.error ? 2 : 0;
    return null;
  }

  const ctx = deps.ctx || buildContext({ cwd: opts.project ? path.resolve(opts.project) : process.cwd() });
  const targets = selectTargets(ctx, { clientIds: opts.clientIds, configFiles: opts.configFiles });
  const unknownClient = opts.clientIds.find((id) => !targets.some((t) => t.id === id));
  if (unknownClient) {
    write(`agentguard ${mode}: unknown client "${unknownClient}"\n${usage(mode)}`);
    process.exitCode = 2;
    return null;
  }

  const plan = planAll(mode, targets, ctx);
  write(`${bold(`AgentGuard ${mode}`)}${opts.apply ? '' : '  (preview — nothing will be changed)'}\n${RULE}\n\n`);
  write(formatPlan(plan) + '\n\n');

  const changing = hasChanges(plan);
  if (!changing) {
    write(mode === 'wrap' ? 'Nothing to wrap: every supported server is already protected or was skipped (see above).\n' : 'Nothing to unwrap.\n');
    return { plan, outcome: null };
  }

  const names = [...new Set(plan.flatMap((t) => t.servers.filter((s) => s.action !== 'skip').map((s) => s.name)))];
  if (mode === 'wrap') {
    write(`Policy: ${ctx.paths.policy}\n  servers you approve by applying: ${names.join(', ')}\n`);
    write(`Audit log: ${ctx.paths.audit}\n\n`);
  }

  if (!opts.apply) {
    write(`Nothing was changed. To ${mode === 'wrap' ? 'apply this' : 'restore these'}: agentguard ${mode} --apply\n`);
    return { plan, outcome: null };
  }

  const outcome = applyPlan(mode, plan, ctx);
  if (outcome.policy?.created) write(`✓ created policy ${ctx.paths.policy}\n`);
  if (outcome.policy?.updated) write(`✓ added to mcp.allowed_servers: ${outcome.policy.added.join(', ')}\n`);
  if (outcome.policy?.notice) write(`⚠ ${outcome.policy.notice}\n`);

  const changedClients = [];
  for (const f of outcome.files) {
    if (f.ok) {
      write(`✓ ${f.client.label}: ${f.changed.join(', ')}\n    backup: ${f.backup}\n`);
      changedClients.push(f.client);
    } else {
      write(`✗ ${f.client.label}: ${f.error}\n`);
      process.exitCode = 1;
    }
  }

  if (changedClients.length) {
    const procs = await (deps.listProcesses || defaultListProcesses)();
    write('\nRestart these apps for the change to take effect:\n');
    for (const c of changedClients) {
      const running = c.processPattern && procs.some((p) => c.processPattern.test(p.name));
      write(`  - ${c.label}${running ? '  (appears to be running now)' : ''}\n`);
    }
    if (mode === 'wrap') write(`\nCheck it: agentguard status      See activity: agentguard events\nUndo it:  agentguard unwrap --apply\n`);
  }
  return { plan, outcome };
}
