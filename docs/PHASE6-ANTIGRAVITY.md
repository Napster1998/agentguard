# Phase 6: Google Antigravity hooks

AgentGuard's original enforcement points (the MCP gateway and
`agentguard exec`) only see what is routed through them. Google Antigravity's
agents do most of their work with **built-in** tools: reading and writing
files, a terminal, and MCP calls. None of those go through an MCP server, so
none of them reached AgentGuard. Phase 6 adds a third entry point that does see
them: an Antigravity `PreToolUse` hook.

```
agentguard hooks --global --apply     # or --workspace <folder>
```

From then on, Antigravity asks AgentGuard before **every** tool call. It does
this by running `agentguard hook antigravity`, which returns `allow` or `deny`
from the same policy engine every other adapter uses.

## How it was built

1. **Read-only feasibility assessment.** It compared the published hook
   contract with AgentGuard's architecture, and found three existing bugs on
   the way (F14–F16).
2. **Validation spike in the real app, before any product code.** A throwaway
   probe hook was installed in a scratch workspace and driven through ten
   scenarios on Windows (Claude Opus, Claude Sonnet and Gemini Flash).
3. **Build in steps, each verified in the real app before commit:**

   | Step | Commit | What it added |
   |---|---|---|
   | 6.1 | `e7cc21f` | file tools + secret checks |
   | 6.2 | `cd50911` | MCP calls |
   | 6.3 | `d0e5dc7` | terminal commands |
   | 6.4 | `d74443e` | installer, self-test, status |
   | 6.5 | `7e7622c`, `9b673e5`, `30ea5cf` | Linux |

## What the spike proved, and where the docs were wrong

| Question | Answer from the real app |
|---|---|
| Does a hook `deny` really stop the tool? | **Yes**, before it runs, in every permission preset (Default, Turbo, Request Review, Auto) and after "always allow". The hook runs **before** Antigravity's own approval prompt. |
| What if the hook crashes, times out or prints garbage? | Antigravity **blocks** the call (fails closed). The docs say plugin hooks fail open; workspace and global hooks do not. Good for security, but a broken install blocks *everything*, which is why the installer self-tests. |
| Which tools are there? | `read_file{Path}`, `write_file`, `edit_file`, `run_command{CommandLine}`, `call_mcp_tool{ServerName,ToolName,Arguments}`, `invoke_subagent`, `send_message`, ... The same for Claude and Gemini. **Not** the `view_file` / `list_dir` / `grep_search` tools the docs list. Folder listing, search and URL fetching all go through the terminal. |
| Which shell runs terminal commands? | Windows PowerShell 5.1 on Windows; non-interactive bash on Linux. |
| Subagents? | Covered. Each has its own conversation id, with no link to the parent. |
| Is `hooks.json` re-read? | Before every tool call, even mid-conversation. Install and removal are instant, but so is tampering, so the agent is denied access to it. |
| Is the payload the same everywhere? | **No.** The Windows App adds `hookEventName` and `cwd`; the Linux build sends the documented shape without them. The installed command therefore names its event (`--event PreToolUse`). |
| Where does the hook's stderr go? | To the model. The hook writes nothing there, and the command uses `--no-warnings`. |

## How a call is judged

- **`read_file` / `write_file` / `edit_file`.** The target path is checked
  against the filesystem rules. Relative paths are resolved against the
  workspace.
- **`run_command` on Windows.** The line is read by **PowerShell's own parser**
  in parse-only mode; it is never run. The fixed parse script is sent as
  `-EncodedCommand`, and the agent's line travels only as data.
  - Every command it contains is checked, including ones inside `{ }` blocks.
  - Aliases count as their command: `rm` and `del` are `Remove-Item`.
  - Literal file arguments, URLs and redirection targets are checked.
  - Some things cannot be evaluated, so they are **blocked** with a named
    rule:
    - a method call;
    - a command whose name is only known at run time;
    - `Invoke-Expression`;
    - a computed argument to anything but a formatting cmdlet;
    - `${C:\file}` variable syntax;
    - a syntax error.
- **`run_command` on Linux.** The strict cross-shell parser (F16) is used,
  which accepts a safe subset of bash.
- **`call_mcp_tool`.** The call goes through the MCP gateway's own translator,
  so remote (HTTP/SSE) servers, which the gateway cannot wrap, are covered.
  Servers already behind the gateway are left to it, so nothing is logged
  twice.
- **Any tool argument.** Known secret patterns are checked in every tool's
  arguments.
- **Flagged, not blocked (WARN):**
  - unlisted terminal commands (the coding-agent profile);
  - commands asking to run outside the sandbox;
  - recursive searches rooted at the home folder or above;
  - tools AgentGuard has no rule for.

The coding-agent profile is `policy/antigravity-policy.yaml`, copied to
`~/.agentguard/antigravity-policy.yaml` on first install and kept separate
from the gateway's policy. It contains:
- the default rules;
- read-only PowerShell commands allowed;
- destructive commands denied;
- `shell.unlisted: warn`;
- **self-protection**: `hooks.json`, Antigravity's MCP config and
  `~/.agentguard` cannot be read or written by the agent.

## Findings fixed along the way

| | Severity | What |
|---|---|---|
| F14 | MEDIUM | Secret values reached the audit log through `agentguard exec` argv and path-shaped values. |
| F15 | MEDIUM | A denied folder itself (`~/.aws`) was not covered by `~/.aws/**`. |
| F16 | HIGH | An MCP shell tool's command string was judged by its first word (`git status && rm -rf ~` was allowed). |
| F17 | MEDIUM | PowerShell's abbreviated `-enc` / `-co` / `/Command` evaded the interpreter-eval check. |
| F18 | MEDIUM | Antigravity terminal: a redirection after an expression (`'x' > file`) and `${C:\file}` were not seen. |

Details and regression tests: [SECURITY-ASSESSMENT.md](../SECURITY-ASSESSMENT.md).

Bugs that were not security findings, but would have hurt users:

- **Linux payload.** Antigravity's Linux build sends no `hookEventName`, so
  every call was denied until the command named its own event.
- **Self-test on Linux.** A Node warning on stderr (`NO_COLOR` together with
  `FORCE_COLOR`) failed the self-test there.
- **Correlation.** A credential read done through the terminal was not counted
  as a read by the correlation rules.

## Real-app results

**Windows** (Antigravity App, PowerShell 5.1):
- **Blocked:**
  - credential reads through `read_file` and through the terminal;
  - `Remove-Item`;
  - a .NET file read;
  - a secret written to a file;
  - a secret sent to an MCP tool;
  - an agent read of `hooks.json`;
  - a credentials read from a folder outside any project (global hook).
- **Flagged:** `curl.exe` and its retry outside the sandbox (WARN).
- **Correlation:** "credential read, then shell" detected.

**Linux** (bash):
- **Flagged:** `ls` (WARN).
- **Blocked:** a credentials `read_file`, `rm`, and the `hooks.json` attempt.
- **Wrapped MCP server:** a call to it was left to the gateway.
- **Correlation:** "credential read, then shell" detected.
- **Refused by the agent itself:** several prompts, before any tool call.
  Those paths are covered by tests.

## Limits

- It covers only what Antigravity routes through the hook. Some app versions
  may send different payloads; a rejected payload is denied (not allowed),
  and `status` says so loudly.
- If Antigravity changes its tool set, unknown tools are WARNed (allowed) and
  listed by `status`.
- What an allowed program does on its own (npm scripts, git config) is not
  judged.
- File targets passed through a PowerShell pipeline are not known.
- A recursive search that starts inside the workspace can reach a credential
  folder inside it.
- PowerShell 7-only syntax is blocked, because the parser is 5.1.
- macOS is untested.
- A parent and its subagents are separate sessions, so a sequence split
  between them is not correlated.
