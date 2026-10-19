import fs from 'node:fs';
import yaml from 'js-yaml';

import { bold } from '../core/colors.js';
import { buildContext, selectTargets, planAll, wrapperProblems } from '../adapters/wrap/orchestrate.js';
import { readEvents } from './events-command.js';

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
