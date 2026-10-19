import os from 'node:os';
import path from 'node:path';

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
} = {}) {
  let claudeDesktop;
  if (platform === 'win32') {
    const appData = env.APPDATA || path.join(homedir, 'AppData', 'Roaming');
    claudeDesktop = path.join(appData, 'Claude', 'claude_desktop_config.json');
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
  ];
}
