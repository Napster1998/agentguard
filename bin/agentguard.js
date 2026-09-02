#!/usr/bin/env node
import { runGatewayCommand } from '../src/cli/gateway-command.js';
import { runScanCommand } from '../src/cli/scan-command.js';
import { runEventsCommand } from '../src/cli/events-command.js';
import { runExecCommand } from '../src/cli/exec-command.js';

const [subcommand, ...rest] = process.argv.slice(2);

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
  default:
    process.stderr.write('Usage: agentguard <gateway|scan|events|exec> [options]\n');
    process.exit(subcommand ? 2 : 0);
}
