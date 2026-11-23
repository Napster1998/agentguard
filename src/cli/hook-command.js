import fs from 'node:fs';
import yaml from 'js-yaml';

import { PolicyEngine, applyDefaults } from '../core/policy-engine.js';
import { AuditLogger } from '../core/audit-logger.js';
import { handleHookInput, recordFailure, deny } from '../adapters/antigravity/hook-handler.js';
import { MAX_PAYLOAD_BYTES } from '../adapters/antigravity/payload.js';
import { antigravityWrappedServers } from '../adapters/antigravity/wrapped-servers.js';
import { USAGE } from './help.js';

const DEFAULT_DEADLINE_MS = 5000;

function parseArgs(argv) {
  const opts = { adapter: argv[0], policyPath: null, logFile: null, deadlineMs: DEFAULT_DEADLINE_MS };
  for (let i = 1; i < argv.length; i++) {
    if (argv[i] === '--policy') opts.policyPath = argv[++i];
    else if (argv[i] === '--log') opts.logFile = argv[++i];
    else if (argv[i] === '--deadline-ms') opts.deadlineMs = Number(argv[++i]) || DEFAULT_DEADLINE_MS;
  }
  return opts;
}

/** Reads stdin to EOF, but gives up as soon as it is over the size limit. */
function readInput(stdin) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    stdin.on('data', (c) => {
      size += c.length;
      if (size > MAX_PAYLOAD_BYTES) {
        stdin.destroy();
        resolve({ tooLarge: true, raw: '' });
        return;
      }
      chunks.push(c);
    });
    stdin.on('end', () => resolve({ tooLarge: false, raw: Buffer.concat(chunks).toString('utf8') }));
    stdin.on('error', reject);
  });
}

const firstLine = (s) => String(s).split(/\r?\n/)[0].slice(0, 200);

/**
 * `agentguard hook antigravity --policy <file> [--log <file>]`
 *
 * Run BY Antigravity as a PreToolUse hook command, once per tool call: reads
 * the hook JSON on stdin, decides, and writes exactly ONE JSON line to stdout.
 *
 * Contract, from the Phase 6 validation spike:
 *  - Antigravity blocks the call if a hook exits non-zero, prints non-JSON,
 *    crashes or times out (fail closed). That protects security, but a broken
 *    hook would block every tool call, so this always answers, always with exit
 *    code 0, and turns anything it cannot handle into an explicit deny whose
 *    reason the model and the user can read.
 *  - Antigravity passes the hook's stderr to the model, so nothing is written
 *    to stderr (the audit log's human mirror is off).
 *  - An internal deadline (default 5 s) answers deny well before Antigravity's
 *    own timeout, so no process is left behind.
 */
export async function runHookCommand(argv, { stdin = process.stdin, stdout = process.stdout, exit = (code) => process.exit(code) } = {}) {
  const opts = parseArgs(argv);
  if (opts.adapter !== 'antigravity') {
    process.stderr.write(`Usage: ${USAGE.hook}\nRun "agentguard hook --help" for details.\n`);
    exit(2);
    return;
  }

  const logger = new AuditLogger({ logFile: opts.logFile, human: false });
  let answered = false;
  let timer;
  const answer = (output) => {
    if (answered) return;
    answered = true;
    clearTimeout(timer);
    stdout.write(JSON.stringify(output) + '\n', () => exit(0));
  };
  const failClosed = (why) => {
    recordFailure(logger, null, why);
    answer(deny(`AgentGuard could not evaluate this call: ${why}`));
  };

  timer = setTimeout(() => failClosed(`it did not finish within ${opts.deadlineMs} ms.`), opts.deadlineMs);

  try {
    if (!opts.policyPath) return failClosed('the hook is misconfigured (no --policy file).');

    let policy;
    try {
      policy = applyDefaults(yaml.load(fs.readFileSync(opts.policyPath, 'utf8')) || {});
    } catch (err) {
      return failClosed(`the policy file could not be loaded (${firstLine(err.message)}).`);
    }

    const { raw, tooLarge } = await readInput(stdin);
    if (answered) return;
    if (tooLarge) return failClosed('the hook input is larger than 1 MiB.');
    const { output } = handleHookInput(raw, {
      engine: new PolicyEngine(policy),
      logger,
      isMcpServerWrapped: antigravityWrappedServers(),
    });
    answer(output);
  } catch (err) {
    failClosed(`an internal error occurred (${firstLine(err && err.message)}).`);
  }
}
