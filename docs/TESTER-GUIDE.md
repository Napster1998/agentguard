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
| Linux (Debian/Ubuntu) | `sudo apt install -y git curl`, then `curl -fsSL https://deb.nodesource.com/setup_lts.x \| sudo -E bash -` and `sudo apt install -y nodejs` (verified end to end on one Linux machine with Google Antigravity; other distros and Claude Desktop on Linux are untested) |

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

**Windows PowerShell:** if `npm` (or later `agentguard`) fails with *"running
scripts is disabled on this system"*, that is Windows' default policy blocking
npm's `.ps1` launcher. It is not a problem with AgentGuard or with your install.
Use `npm.cmd` instead of `npm` (`npm.cmd install`, `npm.cmd test`,
`npm.cmd link`) and `agentguard.cmd` instead of `agentguard`, or run everything
in **Command Prompt**, where it does not happen. (Changing PowerShell's
execution policy also fixes it, but that is a security setting on your account,
so it is your call, not something this guide asks you to do.)

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

## 6. Google Antigravity: protect its built-in tools too (optional)

`wrap` covers MCP servers. Antigravity's own tools (reading and writing files,
the terminal) never go through an MCP server. `agentguard hooks` makes
Antigravity ask AgentGuard before **every** tool call, terminal commands and
MCP calls included.

```bash
agentguard hooks --global          # preview: changes nothing
agentguard hooks --global --apply
```

You can use `--workspace <folder>` instead of `--global` to cover just one
project. No restart is needed: it applies from the next tool call.

`--apply` does the following:
- creates `~/.agentguard/antigravity-policy.yaml`, a coding-agent profile:
  read-only PowerShell commands are allowed, destructive ones (`Remove-Item`,
  `Stop-Process`, ...) are blocked, and anything else runs with a WARN in
  `agentguard events`;
- self-tests the hook command;
- adds one `"agentguard"` entry to `hooks.json`.

To see it work, ask Antigravity: *"Use the terminal to show the contents of
~/.aws/credentials"*. The agent gets `Blocked by AgentGuard policy: ...`, and
`agentguard events` shows a BLOCK. Undo it with
`agentguard hooks remove --global --apply`.

Antigravity **blocks every tool call** if its hook is broken, for example
after you move the agentguard folder or upgrade Node. Run `agentguard status`
to check it. To recover, run `agentguard hooks ... --apply` again to repair
it, or `agentguard hooks remove ... --apply` to take it out.

## Known limits: please read

- **Remote (HTTP/SSE) MCP servers are not protected**, only local (stdio)
  ones. `status` lists each remote server as `NOT protected`.
- **Claude Code's own settings file is never edited**; the app rewrites it
  constantly and editing it risks your settings. `status` lists it as
  "not managed".
- **Claude Desktop from the Microsoft Store (Windows) keeps its live config in a
  different place**: `%LOCALAPPDATA%\Claude-Data\claude_<id>\claude_desktop_config.json`,
  leaving a stale file at the usual `%APPDATA%\Claude\`. AgentGuard looks in both
  and `wrap --apply` protects both. If `status` shows a **Notes** section saying
  Claude Desktop has two config files, that is why; the app reads only one, and
  the newer file is usually it. We found this layout on one machine and it is
  not documented by Anthropic, so if Claude Desktop's tools are still not
  protected after `wrap --apply` and a restart, tell us where its config is.
- **A WARN is not visible in the AI app.** Only BLOCKs show up in the chat.
  Read warnings with `agentguard events`.
- **The default policy is permissive.** Secrets in tool arguments and access to
  any `.ssh` or `.aws` folder (wherever it is) are blocked, but there is no network
  allowlist until you add `network.allowed_domains` to
  `~/.agentguard/policy.yaml`.
- **An existing `~/.agentguard/policy.yaml` is never overwritten.** A newer
  AgentGuard's improved default rules reach only a fresh install. To pick them up,
  compare it with `policy/default-policy.yaml` and copy the new lines in, or move
  your policy aside and run `agentguard wrap --apply` to generate a fresh one.
- **Only apps on AgentGuard's list are found, in their usual places.** For
  another app, or an install in an unusual location, whose config is a JSON file
  with an `mcpServers` section: `agentguard wrap --config <file>`.
- **A project's `.mcp.json` is only found when you run `wrap` from that
  project's folder**, or pass `--project <folder>`.
- **Servers you add later are unprotected** until you run `wrap --apply` again.
  An app update can also rewrite its own config and drop the protection;
  `status` shows it.
- **It only sees traffic routed through it.** A server left unwrapped, or an
  agent that runs shell commands directly, bypasses it. With `agentguard hooks`
  installed, Antigravity's own tools and terminal are covered too.
- **The Antigravity hook is verified on Windows and Linux (one machine each);
  macOS is untested.** On Linux, terminal commands (bash) are read by a strict
  generic parser: a command with `$`, wildcards and the like is blocked rather
  than guessed at.
- **The Antigravity profile is strict about the terminal.** A command it cannot
  read safely (a .NET method call, `Invoke-Expression`, a computed argument,
  PowerShell 7-only syntax like `&&`) is blocked with a reason. Tell us which
  ordinary commands got blocked.

## If something goes wrong

| Symptom | What to do |
|---|---|
| A tool shows as unavailable in the app after `wrap` | `agentguard status`, then read its "Problems" section. A moved or upgraded Node/AgentGuard install is fixed by re-running `agentguard wrap --apply`. |
| `refusing to start ... through cmd.exe` (Windows) | A launcher argument contains `& \| < > ^ % "`. Use the underlying `.exe`, or remove the character. |
| `wrap --apply` said it wrapped Claude Desktop, but its tools are not in `agentguard events` (Windows) | Run `agentguard status`: if it lists two Claude Desktop config files (Notes), the app may use the other one. Re-run `wrap --apply` (it covers both) and fully quit and reopen the app. |
| An app you have installed shows as "not found" | AgentGuard only looks in the usual place. Find the app's MCP config file (a JSON file with an `mcpServers` section) and run `agentguard wrap --config <that file>`. Tell us the app and the path. |
| `events` shows a `DROP` line mentioning "could not be parsed as JSON-RPC" | A server printed something that was not a valid MCP message (Burp's proxy prints `kotlin-log...` lines). AgentGuard does not forward what it cannot inspect, so it dropped that line. No tool call was blocked, and the server keeps working. |
| `status` reports a missing policy file | `agentguard wrap --apply` recreates it (make sure you have pulled the latest code: `git pull`). |
| Antigravity: every tool call says it was blocked by a hook, or "could not evaluate" | `agentguard status`, Antigravity hooks section. If it says the hook cannot start, run `agentguard hooks --global --apply` (or `--workspace ...`) to repair it, or `agentguard hooks remove --global --apply`. Both take effect at once. |
| Antigravity: an ordinary terminal command is blocked | The reason says which rule. Commands you trust can be added to `shell.allowed` in `~/.agentguard/antigravity-policy.yaml`. |
| Want everything back to normal right now | `agentguard unwrap --apply` (MCP servers) and `agentguard hooks remove --global --apply` (Antigravity hook); restart the app after unwrap. |

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
