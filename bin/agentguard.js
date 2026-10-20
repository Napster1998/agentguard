#!/usr/bin/env node
import { runGatewayCommand } from '../src/cli/gateway-command.js';
import { runScanCommand } from '../src/cli/scan-command.js';
import { runEventsCommand } from '../src/cli/events-command.js';
import { runExecCommand } from '../src/cli/exec-command.js';
import { runWrapCommand } from '../src/cli/wrap-command.js';
import { runStatusCommand } from '../src/cli/status-command.js';
import { mainHelp, commandHelp, wantsHelp, USAGE } from '../src/cli/help.js';

const [subcommand, ...rest] = process.argv.slice(2);

// Help is handled here, before any command runs, so `agentguard status --help`
// shows help instead of running status.
if (subcommand === undefined || ['-h', '--help', '--usage', 'help'].includes(subcommand)) {
  const topic = subcommand === 'help' ? rest[0] : undefined;
  if (topic && !commandHelp(topic)) {
    process.stderr.write(`agentguard: unknown command "${topic}"\nRun "agentguard --help" for the list of commands.\n`);
    process.exit(2);
  }
  process.stdout.write(topic ? commandHelp(topic) : mainHelp());
  process.exit(0);
}

if (USAGE[subcommand] && wantsHelp(rest)) {
  process.stdout.write(commandHelp(subcommand));
  process.exit(0);
}

switch (subcommand) {
  case 'gateway':
    runGatewayCommand(rest);
    break;
  case 'scan':
    await runScanCommand(rest);
    break;
  case 'events':
    runEventsCommand(rest);
    break;
  case 'exec':
    await runExecCommand(rest);
    break;
  case 'wrap':
    await runWrapCommand(rest, 'wrap');
    break;
  case 'unwrap':
    await runWrapCommand(rest, 'unwrap');
    break;
  case 'status':
    runStatusCommand(rest);
    break;
  default:
    process.stderr.write(`agentguard: unknown command "${subcommand}"\nRun "agentguard --help" for the list of commands.\n`);
    process.exit(2);
}
