import fs from 'node:fs';
import yaml from 'js-yaml';

import { runScan } from '../adapters/discovery/scan.js';
import { applyDefaults } from '../core/policy-engine.js';

const RULE = '─'.repeat(40);

function parseArgs(argv) {
  const opts = { policyPath: null, json: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--policy') opts.policyPath = argv[++i];
    else if (argv[i] === '--json') opts.json = true;
  }
  return opts;
}

function loadPolicy(policyPath) {
  if (!policyPath) return applyDefaults({});
  const raw = yaml.load(fs.readFileSync(policyPath, 'utf8'));
  return applyDefaults(raw);
}

function severityIcon(severity) {
  return severity === 'CRITICAL' ? '\u{1F6A8}' : '\u{26A0}';
}

export function formatScanReport(posture) {
  const lines = [];
  lines.push('AI Agent Security Scan');
  lines.push(RULE);
  lines.push('');

  lines.push(`✓ Node.js ${process.version} environment detected`);
  if (posture.discoveredAgents.length === 0) {
    lines.push('  (no known local AI/agent runtime detected)');
  } else {
    for (const agent of posture.discoveredAgents) {
      lines.push(`✓ ${agent.label} detected (via ${agent.detectedVia})`);
    }
  }
  if (posture.discoveredMcpServers.length > 0) {
    lines.push(`✓ MCP configuration discovered (${posture.discoveredMcpServers.length} server(s))`);
  }

  if (posture.findings.length > 0) {
    lines.push('');
    for (const f of posture.findings) {
      lines.push(`${severityIcon(f.severity)} [${f.id}] ${f.title}`);
    }
  }

  if (posture.discoveredMcpServers.length > 0) {
    lines.push('');
    lines.push('MCP Servers');
    lines.push(RULE);
    for (const s of posture.discoveredMcpServers) {
      const icon = s.trust === 'trusted' ? '✓' : '⚠';
      lines.push(`${icon} ${s.name.padEnd(20)} ${s.trust.toUpperCase()}`);
    }
  }

  lines.push('');
  lines.push('Security Posture');
  lines.push(RULE);
  lines.push('');
  for (const sev of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
    lines.push(`${sev.padEnd(10)} ${posture.severityCounts[sev]}`);
  }
  lines.push('');
  lines.push(`Score:   ${posture.score}/100`);
  lines.push(`Overall: ${posture.overallRisk}`);

  return lines.join('\n');
}

export async function runScanCommand(argv) {
  const opts = parseArgs(argv);
  const policy = loadPolicy(opts.policyPath);
  const posture = await runScan({ policy });

  if (opts.json) {
    process.stdout.write(JSON.stringify(posture, null, 2) + '\n');
  } else {
    process.stdout.write(formatScanReport(posture) + '\n');
  }

  return posture;
}
