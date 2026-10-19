import fs from 'node:fs';
import os from 'node:os';

import { clientConfigs } from './client-configs.js';

/**
 * Known MCP client config locations, cross-platform, best-effort — NOT
 * exhaustive. Derived from the shared client list (client-configs.js) so the
 * scanner and `agentguard wrap` always look in the same places. Google
 * Antigravity's path (~/.gemini/config/mcp_config.json) is verified on real
 * Windows and macOS installs.
 */
export function knownConfigLocations({ cwd = process.cwd(), platform = process.platform, homedir = os.homedir(), env = process.env } = {}) {
  return clientConfigs({ cwd, platform, homedir, env }).map((c) => c.path);
}

/**
 * Reads and parses known MCP client config files. Only ever reads and
 * JSON.parses these files — never executes a discovered command. A missing
 * file is silently skipped (most locations won't exist on any given
 * machine); a malformed file produces an entry in `errors` instead of
 * throwing, so one bad config can't crash a scan.
 *
 * @returns {{servers: Array<object>, errors: Array<{location:string,message:string}>}}
 */
export function discoverMcpServers({ locations, trustedServerNames = [], readFile = (p) => fs.readFileSync(p, 'utf8') } = {}) {
  const servers = [];
  const errors = [];

  for (const location of locations || knownConfigLocations()) {
    let raw;
    try {
      raw = readFile(location);
    } catch {
      continue; // not present / not readable - not an error, just absent
    }

    // An empty or whitespace-only file is a valid "no servers configured yet"
    // state (Antigravity creates a 0-byte mcp_config.json at install), not a
    // malformed config - don't report it as a parse error.
    if (typeof raw === 'string' && raw.trim() === '') continue;

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (err) {
      errors.push({ location, message: `Malformed JSON: ${err.message}` });
      continue;
    }

    const mcpServers = parsed.mcpServers || parsed.mcp_servers || {};
    for (const [name, def] of Object.entries(mcpServers)) {
      if (!def || typeof def !== 'object') continue;
      servers.push({
        name,
        transport: def.transport || (def.command ? 'stdio' : def.url ? 'http' : 'unknown'),
        command: def.command || null,
        arguments: def.args || [],
        configLocation: location,
        trust: trustedServerNames.includes(name) ? 'trusted' : 'unknown',
      });
    }
  }

  return { servers, errors };
}
