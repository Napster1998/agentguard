/**
 * All of AgentGuard's help text in one place, so the top-level help, each
 * command's --help, and the usage printed on a usage error can't drift apart.
 */

export const COMMANDS = [
  { name: 'wrap', group: 'Protect this machine', summary: 'Route your AI apps\' MCP servers through AgentGuard (preview unless --apply)' },
  { name: 'unwrap', group: 'Protect this machine', summary: 'Undo wrap: restore every original entry (preview unless --apply)' },
  { name: 'status', group: 'Protect this machine', summary: 'Show what is protected, what is not, and why' },
  { name: 'events', group: 'See what happened', summary: 'Show the audit log: each ALLOW / WARN / BLOCK decision, and any risky pattern' },
  { name: 'scan', group: 'See what happened', summary: 'Assess this machine\'s AI-agent security posture (read-only)' },
  { name: 'gateway', group: 'Lower level', summary: 'Run ONE MCP server behind the policy gateway (what wrap sets up for you)' },
  { name: 'exec', group: 'Lower level', summary: 'Run ONE shell command through the same policy; BLOCK means it never starts' },
];

/** One-line usage per command (also what a usage ERROR prints to stderr). */
export const USAGE = {
  wrap: 'agentguard wrap [--apply] [--client <id>]... [--config <file>]... [--project <dir>]',
  unwrap: 'agentguard unwrap [--apply] [--client <id>]... [--config <file>]... [--project <dir>]',
  status: 'agentguard status [--project <dir>]',
  events: 'agentguard events [--log <file>] [--session <id>] [--risk <level>] [--blocked]',
  scan: 'agentguard scan [--policy <policy.yaml>] [--json]',
  gateway: 'agentguard gateway --policy <policy.yaml> [--log <file>] [--server-name <name>] -- <command> [args...]',
  exec: 'agentguard exec --policy <policy.yaml> [--log <file>] -- <command> [args...]',
};

const DETAIL = {
  wrap: `Finds the MCP servers configured in your AI apps (Claude Desktop, Google
Antigravity, a project's .mcp.json) and rewrites each local one to run through
AgentGuard. With no --apply it only PREVIEWS: it changes nothing.

  --apply          back up each config file, then make the change. Restart the
                   AI app afterwards.
  --client <id>    only this app: claude-desktop, antigravity, claude-code-project
  --config <file>  a JSON file with an "mcpServers" section, for an app not on
                   the list (when given, ONLY these files are considered)
  --project <dir>  look for a project .mcp.json in <dir> instead of the current folder

Remote (HTTP/SSE) servers are skipped and reported, not hidden. Undo: agentguard unwrap --apply`,

  unwrap: `Restores every MCP server entry that wrap rewrote to its original command.
With no --apply it only PREVIEWS. Your policy and audit log are kept.

  --apply          restore the entries (each file is backed up first)
  --client <id>    only this app: claude-desktop, antigravity, claude-code-project
  --config <file>  a JSON file with an "mcpServers" section (only these files)
  --project <dir>  look for a project .mcp.json in <dir> instead of the current folder`,

  status: `Read-only. For each AI app AgentGuard knows about, shows which MCP servers
are protected, which are not and why, and any problem that would stop a
protected server from starting. Also shows where the policy and audit log are.

  --project <dir>  look for a project .mcp.json in <dir> instead of the current folder`,

  events: `Reads the audit log and shows, per session, every decision AgentGuard made
(ALLOW / WARN / BLOCK, risk, and the reason), plus any risky pattern across a
session's events.

  --log <file>     audit log to read (default: ~/.agentguard/audit.jsonl)
  --session <id>   only this session
  --risk <level>   only events with exactly this risk: LOW, MEDIUM, HIGH or CRITICAL
                   (a pattern spanning other levels is still reported)
  --blocked        only BLOCK decisions`,

  scan: `Read-only assessment of this machine: which AI agents are running, which MCP
servers are configured, whether anything is exposed beyond localhost, and
whether sensitive files exist. It never modifies a file, never runs a
configured server, and never reads a secret's contents.

  --policy <file>  policy used to decide which MCP servers count as trusted
                   (default: ~/.agentguard/policy.yaml if it exists, else the
                   built-in defaults)
  --json           print the full result as JSON`,

  gateway: `Runs one MCP server behind AgentGuard. The AI app talks to this command
instead of the server; every tool call is checked against the policy first.
\`agentguard wrap\` sets this up for you; use it directly only for a server it
cannot wrap.

  --policy <file>       policy to enforce (required)
  --log <file>          where to write the audit log
  --server-name <name>  the name this server is known by in the policy and log
  --                    everything after this is the server's own command`,

  exec: `Runs one shell command through the same policy. The command is checked
BEFORE it starts: on BLOCK it never runs. Only commands you route through this
are covered; it does not watch anything else on the machine.

  --policy <file>  policy to enforce (required)
  --log <file>     where to write the audit log
  --               everything after this is the command to run`,
};

export function mainHelp() {
  const groups = [];
  for (const c of COMMANDS) {
    let g = groups.find((x) => x.name === c.group);
    if (!g) groups.push((g = { name: c.group, items: [] }));
    g.items.push(c);
  }
  const width = Math.max(...COMMANDS.map((c) => c.name.length)) + 2;
  const sections = groups.map((g) => `${g.name}\n${g.items.map((c) => `  ${c.name.padEnd(width)}${c.summary}`).join('\n')}`);

  return `AgentGuard: a local security gateway for AI agents. It checks MCP tool calls
(and shell commands you route through it) against a written policy and records
every decision. It enforces rules; it does not judge intent.

Usage: agentguard <command> [options]

${sections.join('\n\n')}

Typical flow
  agentguard wrap             preview what would change (nothing is modified)
  agentguard wrap --apply     do it (each config is backed up first), then restart your AI app
  agentguard status           check every server says "protected"
  agentguard events           see what the agents did
  agentguard unwrap --apply   undo

More: agentguard <command> --help   |   README.md, docs/TESTER-GUIDE.md
`;
}

/** Full help for one command, or null if there is no such command. */
export function commandHelp(name) {
  if (!USAGE[name]) return null;
  return `Usage: ${USAGE[name]}\n\n${DETAIL[name]}\n`;
}

/**
 * Is a help flag being asked for? Only flags BEFORE a standalone `--` count:
 * after it, arguments belong to the wrapped command (`gateway -- npx --help`
 * must pass --help to npx, not print AgentGuard's help).
 */
export function wantsHelp(args) {
  for (const a of args) {
    if (a === '--') return false;
    if (a === '-h' || a === '--help') return true;
  }
  return false;
}
