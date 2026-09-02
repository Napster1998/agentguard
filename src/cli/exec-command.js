import fs from 'node:fs';
import yaml from 'js-yaml';

import { applyDefaults } from '../core/policy-engine.js';
import { runExec } from '../adapters/shell/exec-wrapper.js';

function usage() {
  process.stderr.write('Usage: agentguard exec --policy <policy.yaml> [--log <file>] -- <command> [args...]\n');
}

function parseArgs(argv) {
  const sepIndex = argv.indexOf('--');
  if (sepIndex === -1) {
    usage();
    process.exit(2);
  }

  const wrapperArgs = argv.slice(0, sepIndex);
  const command = argv.slice(sepIndex + 1);
  if (command.length === 0) {
    process.stderr.write('Missing command to run after --\n');
    process.exit(2);
  }

  const opts = { policyPath: null, logFile: null };
  for (let i = 0; i < wrapperArgs.length; i++) {
    if (wrapperArgs[i] === '--policy') opts.policyPath = wrapperArgs[++i];
    else if (wrapperArgs[i] === '--log') opts.logFile = wrapperArgs[++i];
  }

  return { opts, command };
}

/** `agentguard exec` — evaluates a command against policy before ever
 * spawning it. See src/adapters/shell/exec-wrapper.js for the enforcement
 * mechanism and its documented trust boundary. */
export async function runExecCommand(argv) {
  const { opts, command } = parseArgs(argv);

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
  const result = await runExec({ policy, command: command[0], args: command.slice(1), logFile: opts.logFile });

  if (!result.executed) {
    process.stderr.write(`BLOCKED by AgentGuard policy: ${result.decision.reason}\n`);
  }

  process.exitCode = result.exitCode;
}
