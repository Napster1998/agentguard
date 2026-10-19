#!/usr/bin/env node
import { runGatewayCommand } from '../src/cli/gateway-command.js';
import { runScanCommand } from '../src/cli/scan-command.js';
import { runEventsCommand } from '../src/cli/events-command.js';
import { runExecCommand } from '../src/cli/exec-command.js';
import { runWrapCommand } from '../src/cli/wrap-command.js';
import { runStatusCommand } from '../src/cli/status-command.js';

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
    process.stderr.write('Usage: agentguard <wrap|unwrap|status|scan|events|gateway|exec> [options]\n');
    process.exit(subcommand ? 2 : 0);
}
