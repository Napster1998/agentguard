#!/usr/bin/env node
import { runGatewayCommand } from '../src/cli/gateway-command.js';

runGatewayCommand(process.argv.slice(2));
