import os from 'node:os';

import { clientConfigs } from '../discovery/client-configs.js';
import { readConfigFile, serverTable } from '../wrap/config-file.js';
import { isWrappedEntry } from '../wrap/plan.js';

/**
 * Which of Antigravity's MCP servers already run behind the AgentGuard gateway
 * (`agentguard wrap`). A call to one of those is checked by the gateway, with
 * response inspection the hook cannot do, so the hook leaves it alone rather
 * than evaluate and log the same call twice (Phase 6 decision D3).
 *
 * Read fresh on every hook call (the file is small, and wrap/unwrap must take
 * effect at once). If the config cannot be read, NO server counts as wrapped:
 * the safe direction is to evaluate a call twice, never zero times.
 *
 * @returns {(serverName: string) => boolean}
 */
export function antigravityWrappedServers({ env = process.env, homedir = os.homedir() } = {}) {
  let wrapped = new Set();
  try {
    const config = clientConfigs({ env, homedir }).find((c) => c.id === 'antigravity');
    const info = readConfigFile(config.path);
    wrapped = new Set(
      Object.entries(serverTable(info))
        .filter(([, def]) => isWrappedEntry(def))
        .map(([name]) => name)
    );
  } catch {
    /* absent or unreadable config: nothing is wrapped */
  }
  return (serverName) => wrapped.has(serverName);
}
