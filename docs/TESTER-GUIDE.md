# AgentGuard tester guide

For people trying AgentGuard on a machine that already has an AI app with MCP
tools connected (Claude Desktop, Google Antigravity, or a project `.mcp.json`).
Takes about 10 minutes. Everything it changes can be undone with one command.

## What it does, and what it doesn't

AgentGuard sits between your AI app and each MCP tool server. Before a tool
call reaches the server it checks a written policy:

- **ALLOW**: passes through, recorded in the audit log.
- **WARN**: passes through, recorded as a warning in the audit log.
- **BLOCK**: never reaches the server. Your AI app shows an error that says
  `Blocked by AgentGuard policy: <the reason>`.

It does **not** judge whether the AI is "good" or "evil", and it is **not** an
antivirus or a sandbox. It enforces rules you can read. It only sees tool calls
that pass through it (see "Known limits").

## 1. Install

You need **Node.js 20 or newer** and **git**. If you have neither:

| System | Commands |
|---|---|
| Windows (PowerShell) | `winget install OpenJS.NodeJS.LTS` and `winget install Git.Git`, then open a new terminal |
| macOS | install [Homebrew](https://brew.sh), then `brew install node git` |
| Linux (Debian/Ubuntu) | `sudo apt install -y git curl`, then `curl -fsSL https://deb.nodesource.com/setup_lts.x \| sudo -E bash -` and `sudo apt install -y nodejs` (we have not tested Linux ourselves) |

Then:

```bash
git clone https://github.com/Napster1998/agentguard.git
cd agentguard
npm install
npm test          # optional: should end with "fail 0"
npm link          # optional: gives you a global `agentguard` command
```

Without `npm link`, replace `agentguard` below with `node bin/agentguard.js`
(run from the `agentguard` folder). If `npm link` fails with a permissions
error (EACCES), don't use `sudo`: skip it and use `node bin/agentguard.js`.

## 2. Look first (changes nothing)

```bash
agentguard --help
agentguard scan
agentguard wrap
```

`agentguard --help` lists every command; `agentguard <command> --help` explains
one (for example `agentguard wrap --help`).

`wrap` with no options is a **preview**. It lists every app and MCP server it
found, says what it would change, and changes nothing. It never prints your
tool arguments or environment variables (those can hold API tokens).

## 3. Protect

```bash
agentguard wrap --apply
```

For each app it: backs up the config file (to `~/.agentguard/backups/`),
rewrites each local MCP server's entry to run through AgentGuard, and creates
`~/.agentguard/policy.yaml` (the default policy plus the servers it just
wrapped). Then **restart the AI app** (fully quit it, not just close the
window). Check it:

```bash
agentguard status
```

You want every server to say `protected`. Anything else tells you why.

## 4. Try it

In your AI app, ask it to use one of its MCP tools normally. Then:

```bash
agentguard events
```

You should see an `ALLOW` line for that call. To see a BLOCK safely, ask the
app to pass this fake AWS example key (from AWS's own documentation, not a real
credential) to any tool that takes text:

```
AKIAIOSFODNN7EXAMPLE
```

The app may report `Blocked by AgentGuard policy: ... aws-access-key-id`, and
`agentguard events` shows a `BLOCK`. **Trust `events`, not the chat:** some apps
summarize a tool error instead of showing it (one called it a "connector
hiccup"), and the model may still print the string itself, because AgentGuard
stops the tool call, not what the model says. Some AI services also filter such
strings themselves before any tool is called; if so, nothing reaches AgentGuard
and nothing is logged. All of that is normal.

## 5. Undo

```bash
agentguard unwrap --apply
```

Restores every wrapped entry to its original command and leaves everything else
in the file alone. Restart the app again. (Your policy and audit log in
`~/.agentguard` are kept.) The exact original of each file is also in
`~/.agentguard/backups/`.

## Known limits: please read

- **Remote (HTTP/SSE) MCP servers are not protected**, only local (stdio)
  ones. `status` lists each remote server as `NOT protected`.
- **Claude Code's own settings file is never edited**; the app rewrites it
  constantly and editing it risks your settings. `status` lists it as
  "not managed".
- **A WARN is not visible in the AI app.** Only BLOCKs show up in the chat.
  Read warnings with `agentguard events`.
- **The default policy is permissive.** Secrets in tool arguments and access to
  paths like `~/.ssh` and `~/.aws` are blocked, but there is no network
  allowlist until you add `network.allowed_domains` to
  `~/.agentguard/policy.yaml`.
- **Only apps on AgentGuard's list are found, in their usual places.** For
  another app, or an install in an unusual location, whose config is a JSON file
  with an `mcpServers` section: `agentguard wrap --config <file>`.
- **A project's `.mcp.json` is only found when you run `wrap` from that
  project's folder**, or pass `--project <folder>`.
- **Servers you add later are unprotected** until you run `wrap --apply` again.
  An app update can also rewrite its own config and drop the protection;
  `status` shows it.
- **It only sees traffic routed through it.** A server left unwrapped, or an
  agent that runs shell commands directly, bypasses it.

## If something goes wrong

| Symptom | What to do |
|---|---|
| A tool shows as unavailable in the app after `wrap` | `agentguard status`, then read its "Problems" section. A moved or upgraded Node/AgentGuard install is fixed by re-running `agentguard wrap --apply`. |
| `refusing to start ... through cmd.exe` (Windows) | A launcher argument contains `& \| < > ^ % "`. Use the underlying `.exe`, or remove the character. |
| An app you have installed shows as "not found" | AgentGuard only looks in the usual place. Find the app's MCP config file (a JSON file with an `mcpServers` section) and run `agentguard wrap --config <that file>`. Tell us the app and the path. |
| `status` reports a missing policy file | `agentguard wrap --apply` recreates it (make sure you have pulled the latest code: `git pull`). |
| Want everything back to normal right now | `agentguard unwrap --apply`, then restart the app. |

## What to send back

Run these and send the output:

```bash
agentguard status
agentguard events
```

**Look them over first.** They never contain secret values, file contents or
tool arguments as such, but they do contain your computer username (in file
paths), the paths of config files, and the file paths and website names that
tool calls touched (for example `filesystem:/Users/you/project/notes.txt`). Black
out anything you would rather not share.

And tell us: which app, which OS, what you expected, and what actually
happened. Anything that broke a tool that worked before is the most valuable
thing you can report.
