#!/usr/bin/env node
import { runGatewayCommand } from '../src/cli/gateway-command.js';
import { runScanCommand } from '../src/cli/scan-command.js';
import { runEventsCommand } from '../src/cli/events-command.js';

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
  default:
    process.stderr.write('Usage: agentguard <gateway|scan|events> [options]\n');
    process.exit(subcommand ? 2 : 0);
}
