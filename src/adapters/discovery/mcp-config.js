import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Known MCP client config locations, cross-platform, best-effort — NOT
 * exhaustive. A project-level .mcp.json, Claude Code's global config,
 * Claude Desktop's per-OS config path, and Google Antigravity's global MCP
 * config (~/.gemini/config/mcp_config.json - verified on a real Windows
 * install; assumed to be the same home-relative path on macOS/Linux, which
 * has not been verified on a real install).
 */
export function knownConfigLocations({ cwd = process.cwd(), platform = process.platform, homedir = os.homedir() } = {}) {
  const locations = [
    path.join(cwd, '.mcp.json'),
    path.join(homedir, '.claude.json'),
    path.join(homedir, '.gemini', 'config', 'mcp_config.json'),
  ];

  if (platform === 'win32') {
    const appData = process.env.APPDATA || path.join(homedir, 'AppData', 'Roaming');
    locations.push(path.join(appData, 'Claude', 'claude_desktop_config.json'));
  } else if (platform === 'darwin') {
    locations.push(path.join(homedir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json'));
  } else {
    locations.push(path.join(homedir, '.config', 'Claude', 'claude_desktop_config.json'));
  }

  return locations;
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
