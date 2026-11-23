import fs from 'node:fs';
import os from 'node:os';
import yaml from 'js-yaml';

import { bold } from '../core/colors.js';
import { buildContext, selectTargets, planAll, wrapperProblems, duplicateClientNotes } from '../adapters/wrap/orchestrate.js';
import { readEvents } from './events-command.js';
import { hookLocations } from './hooks-command.js';
import { buildHookCommand } from '../adapters/antigravity/hooks-config.js';

const HOOK_MARK = { installed: '✓', stale: '⚠', disabled: '⚠', foreign: '⚠', unparseable: '⚠', none: '·', absent: '·' };
const HOOK_TEXT = {
  installed: 'protected (AgentGuard hook installed)',
  stale: 'AgentGuard hook installed with different paths: run agentguard hooks ... --apply to repair',
  disabled: 'AgentGuard hook present but "enabled": false, so NOT checking anything',
  foreign: 'an "agentguard" entry that is not AgentGuard\'s hook',
  unparseable: 'hooks.json is not valid JSON',
  none: 'no AgentGuard hook',
  absent: 'no hooks.json',
};

/**
 * The Antigravity hook part of `status`: where it is installed, whether its
 * command would start (a failing hook makes Antigravity block EVERY tool call),
 * when it last ran, and which tools it has seen that it has no rule for.
 */
export function formatHooksSection(ctx, events) {
  let command = null;
  try {
    command = buildHookCommand({ policyPath: ctx.paths.antigravityPolicy || '', logPath: ctx.paths.audit });
  } catch {
    /* unsafe install path: every location then reads as "stale" */
  }
  const locations = hookLocations({ workspace: ctx.cwd || process.cwd(), homedir: ctx.homedir || os.homedir(), command });
  const lines = [bold('Antigravity hooks')];
  for (const l of locations) lines.push(`${HOOK_MARK[l.state]} ${l.label}: ${HOOK_TEXT[l.state]}`, `    ${l.file}`);

  const problems = [];
  const active = locations.filter((l) => ['installed', 'stale', 'disabled'].includes(l.state));
  for (const l of active) {
    const quoted = [...(l.command || '').matchAll(/"([^"]+)"/g)].map((m) => m[1]);
    const missing = quoted.slice(0, 3).filter((p) => !fs.existsSync(p)); // node, agentguard.js, policy
    if (missing.length && l.state !== 'disabled') {
      problems.push(`${l.label}: the hook cannot start (missing ${missing.join(', ')}), so Antigravity will BLOCK every tool call. Run agentguard hooks ... --apply, or agentguard hooks remove ... --apply.`);
    }
  }
  if (active.length > 1) problems.push('AgentGuard is installed globally AND in this workspace: every tool call is checked, and logged, twice.');

  const mine = events.filter((e) => e.source === 'antigravity-hook');
  const last = mine.map((e) => e.timestamp).filter(Boolean).sort().pop();
  // Every recent decision a rejection of Antigravity's input: the hook is
  // blocking every tool call (found in Phase 6.5: Linux sends a different payload).
  const recent = [...mine].sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || '')).slice(-3);
  if (recent.length && recent.every((e) => e.rule === 'malformed-hook-input')) {
    const keys = recent.map((e) => e.metadata?.payloadKeys).find(Boolean);
    problems.push(
      `The hook's last ${recent.length} decision(s) all rejected Antigravity's input ("${String(recent[recent.length - 1].reason).slice(0, 120)}"), so Antigravity is blocking every tool call. Remove it (agentguard hooks remove ... --apply) and report this${keys ? `; fields received: ${keys.join(', ')}` : ''}.`
    );
  }
  if (active.length) lines.push(`  last hook decision: ${last || 'none yet (it records the first tool call Antigravity makes)'}`);
  const unknown = [...new Set(mine.flatMap((e) => [...String(e.resource || '').matchAll(/agent-tool:([\w.-]+)/g)].map((m) => m[1])))];
  if (unknown.length) lines.push(`  tools without a rule (allowed with WARN): ${unknown.join(', ')}`);
  for (const p of problems) lines.push(`  ⚠ ${p}`);
  return { lines, problems };
}

const RULE = '─'.repeat(40);

/**
 * `agentguard status`: read-only. Shows, for every client AgentGuard knows
 * about, which MCP servers are protected and which are not (and why), plus
 * the health of the policy and audit log. A miss is meant to be visible.
 */
export function formatStatus(plan, ctx) {
  const lines = [bold('AgentGuard status'), RULE, ''];

  lines.push(`Home:   ${ctx.paths.home}`);
  if (fs.existsSync(ctx.paths.policy)) {
    let approved = '?';
    try {
      const list = yaml.load(fs.readFileSync(ctx.paths.policy, 'utf8'))?.mcp?.allowed_servers;
      approved = Array.isArray(list) ? `${list.length} approved server(s)` : 'no allowlist';
    } catch {
      approved = 'unreadable (invalid YAML)';
    }
    lines.push(`Policy: ${ctx.paths.policy}  (${approved})`);
  } else {
    lines.push('Policy: none yet (created by `agentguard wrap --apply`)');
  }
  const events = readEvents(ctx.paths.audit);
  const last = events.map((e) => e.timestamp).filter(Boolean).sort().pop();
  lines.push(`Audit:  ${ctx.paths.audit}  (${events.length} event(s)${last ? `, last ${last}` : ''})`);
  lines.push('');

  let protectedCount = 0;
  let repairCount = 0;
  let unprotectedCount = 0;
  lines.push(bold('Clients'));
  for (const t of plan) {
    if (t.status === 'absent') {
      lines.push(`· ${t.client.label}: not found`);
      continue;
    }
    if (t.status === 'unparseable') {
      lines.push(`⚠ ${t.client.label}: ${t.error}`);
      continue;
    }
    if (t.status === 'unsupported') {
      lines.push(`· ${t.client.label}: ${t.servers.length} server(s), not managed by AgentGuard (${t.client.reason})`);
      unprotectedCount += t.servers.length;
      continue;
    }
    lines.push(`${t.servers.length ? '✓' : '·'} ${t.client.label}  ${t.file}`);
    if (t.status === 'no-servers') lines.push('    no MCP servers configured');
    for (const s of t.servers) {
      if (s.state === 'wrapped') {
        protectedCount++;
        lines.push(`    ✓ ${s.name.padEnd(18)} protected`);
      } else if (s.state === 'stale') {
        repairCount++;
        lines.push(`    ⚠ ${s.name.padEnd(18)} wrapped, but needs repair (agentguard wrap --apply)`);
      } else if (s.state === 'remote') {
        unprotectedCount++;
        lines.push(`    ⚠ ${s.name.padEnd(18)} NOT protected: ${s.reason}`);
      } else if (s.state === 'unwrapped') {
        unprotectedCount++;
        lines.push(`    ⚠ ${s.name.padEnd(18)} NOT protected (agentguard wrap --apply)`);
      } else {
        unprotectedCount++;
        lines.push(`    ⚠ ${s.name.padEnd(18)} NOT protected: ${s.reason}`);
      }
    }
  }

  const hooks = formatHooksSection(ctx, events);
  lines.push('', ...hooks.lines);

  const notes = duplicateClientNotes(plan);
  if (notes.length) {
    lines.push('', bold('Notes'));
    for (const n of notes) lines.push(n.startsWith('    ') ? n : `  ⚠ ${n}`);
  }

  const problems = wrapperProblems(plan, ctx);
  if (problems.length) {
    lines.push('', bold('Problems'));
    for (const p of problems) lines.push(`  ⚠ ${p}`);
  }

  const repair = repairCount ? `, ${repairCount} needs repair` : '';
  const seeProblems = problems.length ? ' See Problems above: a server listed as protected may still fail to start.' : '';
  lines.push('', `${protectedCount} protected${repair}, ${unprotectedCount} not protected.${seeProblems}`);
  lines.push('Apps not on AgentGuard\'s list are not covered; use `agentguard wrap --config <file>` for a JSON file with an "mcpServers" section.');
  return lines.join('\n');
}

export function runStatusCommand(argv, deps = {}) {
  const write = deps.write || ((s) => process.stdout.write(s));
  const project = argv.includes('--project') ? argv[argv.indexOf('--project') + 1] : null;
  const ctx = deps.ctx || buildContext({ cwd: project ? project : process.cwd() });
  const plan = planAll('wrap', selectTargets(ctx), ctx);
  write(formatStatus(plan, ctx) + '\n');
  return plan;
}
