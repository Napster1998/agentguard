import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Claude Desktop installed from the Microsoft Store runs sandboxed (MSIX), and
 * keeps its LIVE config under
 *   %LOCALAPPDATA%\Claude-Data\claude_<package id>\claude_desktop_config.json
 * instead of the usual %APPDATA%\Claude\ (which, there, is a stale leftover).
 * The package id differs per install, so it is found by pattern. Observed on a
 * real Store install; Anthropic does not document it, so a miss is possible.
 * Only config files that actually exist are returned.
 */
function storeClaudeDesktopConfigs({ env, homedir, readdir, exists }) {
  const localAppData = env.LOCALAPPDATA || path.join(homedir, 'AppData', 'Local');
  const root = path.join(localAppData, 'Claude-Data');
  let names = [];
  try {
    names = readdir(root);
  } catch {
    return []; // no Store install (or unreadable): nothing to add
  }
  return names
    .filter((n) => /^claude_/i.test(n))
    .sort()
    .map((n) => path.join(root, n, 'claude_desktop_config.json'))
    .filter((p) => exists(p));
}

/**
 * The single list of "where does each MCP client keep its server settings".
 * Shared by the scanner (read-only discovery) and `agentguard wrap`
 * (rewriting), so the two cannot drift apart.
 *
 * Best-effort and deliberately incomplete: a client that is not listed here
 * is simply not seen. Adding one is a data edit in this function.
 *
 * `wrappable: false` entries are DISCOVERED but never rewritten, with the
 * reason shown to the user.
 *
 * @returns {Array<{id:string,label:string,path:string,wrappable:boolean,reason?:string,processPattern?:RegExp}>}
 */
export function clientConfigs({
  cwd = process.cwd(),
  platform = process.platform,
  homedir = os.homedir(),
  env = process.env,
  readdir = (p) => fs.readdirSync(p),
  exists = (p) => fs.existsSync(p),
} = {}) {
  let claudeDesktop;
  let storeInstalls = [];
  if (platform === 'win32') {
    const appData = env.APPDATA || path.join(homedir, 'AppData', 'Roaming');
    claudeDesktop = path.join(appData, 'Claude', 'claude_desktop_config.json');
    storeInstalls = storeClaudeDesktopConfigs({ env, homedir, readdir, exists });
  } else if (platform === 'darwin') {
    claudeDesktop = path.join(homedir, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
  } else {
    claudeDesktop = path.join(homedir, '.config', 'Claude', 'claude_desktop_config.json');
  }

  return [
    {
      id: 'claude-code-project',
      label: 'Claude Code (project .mcp.json)',
      path: path.join(cwd, '.mcp.json'),
      wrappable: true,
    },
    {
      id: 'claude-code-user',
      label: 'Claude Code (user settings)',
      path: path.join(homedir, '.claude.json'),
      wrappable: false,
      reason: 'this file is owned and continuously rewritten by Claude Code itself; editing it risks corrupting its settings',
    },
    {
      id: 'antigravity',
      label: 'Google Antigravity',
      path: path.join(homedir, '.gemini', 'config', 'mcp_config.json'),
      wrappable: true,
      processPattern: /antigravity/i,
    },
    {
      id: 'claude-desktop',
      label: 'Claude Desktop',
      path: claudeDesktop,
      wrappable: true,
      processPattern: /(^|[\\/])claude(\.exe)?$|Claude\.app/i,
    },
    // Same app, same id (so `--client claude-desktop` covers every copy); the
    // label says which copy it is. When both exist the app reads only one:
    // `status` points that out instead of guessing which.
    ...storeInstalls.map((p) => ({
      id: 'claude-desktop',
      label: 'Claude Desktop (Microsoft Store install)',
      path: p,
      wrappable: true,
    })),
  ];
}
