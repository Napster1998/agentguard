import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';

import { applyDefaults } from '../core/policy-engine.js';
import { startProxy } from '../adapters/mcp/proxy.js';
import { SpawnRefusal } from '../adapters/host/spawn-target.js';

function usage() {
  process.stderr.write(
    'Usage: agentguard gateway --policy <policy.yaml> [--log <file>] [--server-name <name>] -- <command> [args...]\n'
  );
}

function parseArgs(argv) {
  const sepIndex = argv.indexOf('--');
  if (sepIndex === -1) {
    usage();
    process.exit(2);
  }

  const gatewayArgs = argv.slice(0, sepIndex);
  const serverCmd = argv.slice(sepIndex + 1);
  if (serverCmd.length === 0) {
    process.stderr.write('Missing downstream MCP server command after --\n');
    process.exit(2);
  }

  const opts = { policyPath: null, logFile: null, serverName: null };
  for (let i = 0; i < gatewayArgs.length; i++) {
    const arg = gatewayArgs[i];
    if (arg === '--policy') opts.policyPath = gatewayArgs[++i];
    else if (arg === '--log') opts.logFile = gatewayArgs[++i];
    else if (arg === '--server-name') opts.serverName = gatewayArgs[++i];
  }

  return { opts, serverCmd };
}

/** Entry point shared by `bin/agentguard-gateway.js` and `agentguard gateway`. */
export function runGatewayCommand(argv) {
  const { opts, serverCmd } = parseArgs(argv);

  if (!opts.policyPath) {
    process.stderr.write('--policy <file> is required\n');
    usage();
    process.exit(2);
  }

  let policyRaw;
  try {
    policyRaw = yaml.load(fs.readFileSync(opts.policyPath, 'utf8'));
  } catch (err) {
    process.stderr.write(`Failed to load policy file "${opts.policyPath}": ${err.message}\n`);
    process.exit(2);
  }

  const policy = applyDefaults(policyRaw);
  const serverName = opts.serverName || path.basename(serverCmd[0]);

  try {
    return startProxy({
      policy,
      serverCommand: serverCmd[0],
      serverArgs: serverCmd.slice(1),
      logFile: opts.logFile,
      serverName,
    });
  } catch (err) {
    if (!(err instanceof SpawnRefusal)) throw err;
    process.stderr.write(`[AgentGuard] ${err.message}\n`);
    process.exit(1);
  }
}
