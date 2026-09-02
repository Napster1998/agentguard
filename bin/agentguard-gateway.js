#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';

import { applyDefaults } from '../src/core/policy-engine.js';
import { startProxy } from '../src/adapters/mcp/proxy.js';

function usage() {
  process.stderr.write(
    'Usage: agentguard-gateway --policy <policy.yaml> [--log <file>] [--server-name <name>] -- <command> [args...]\n'
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

const { opts, serverCmd } = parseArgs(process.argv.slice(2));

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

startProxy({
  policy,
  serverCommand: serverCmd[0],
  serverArgs: serverCmd.slice(1),
  logFile: opts.logFile,
  serverName,
});
