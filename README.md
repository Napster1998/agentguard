# AgentGuard — MCP Security Gateway (Phase 1 POC)

> **This is a DevDay proof-of-concept, not a production EDR or a complete AI
> security platform.** It demonstrates one thing end-to-end: a real MCP
> stdio proxy that intercepts tool calls, evaluates them against a
> deterministic policy, and enforces ALLOW/WARN/BLOCK. Everything else in the
> broader vision (posture scanner, shell/network adapters, anomaly detection)
> is explicitly out of scope for this phase — see [Phase 2](#phase-2).

## The problem

Developers install local AI agent tooling (agent harnesses, MCP servers,
local model runtimes) on the same machines that hold source code, `.env`
files, SSH keys, and cloud credentials. A vulnerability scanner can tell you
the *software* is configured insecurely; it cannot tell you **what the agent
actually did at runtime** — did it read `~/.ssh/id_rsa`? Did it shell out to
`curl` and send data somewhere? That is the question this gateway answers.

We are not attempting to classify "malicious AI" or infer intent. We model
**capabilities, resources, actions, policies, and violations**, and enforce
deterministic rules against them:

```
Agent
  |
  +--> Action: READ
  |
  +--> Resource: ~/.aws/credentials
  |
  +--> Policy: filesystem.deny
  |
  +--> Decision: BLOCK  (risk: CRITICAL)
```

## Architecture

```
Developer
    |
    v
AI Agent / Harness  (Claude Code, Claude Desktop, etc.)
    |  spawns, over stdio, as its configured "MCP server"
    v
+----------------------------------------------------+
|                  AgentGuard Gateway                 |
|                                                      |
|  MCP adapter (translate.js)                         |
|    tools/call JSON-RPC  --->  generic Action[]       |
|                                                      |
|  Policy Engine (policy-engine.js)                    |
|    Action  --->  Decision {ALLOW | WARN | BLOCK}      |
|                                                      |
|  Audit Logger (audit-logger.js)                      |
|    every decision -> JSONL + human-readable stderr   |
+----------------------------------------------------+
    |  spawns, over stdio, the real command
    v
Real MCP Server  (e.g. @modelcontextprotocol/server-filesystem)
```

The gateway is itself an MCP "server" from the agent's point of view, and an
MCP "client" from the real server's point of view — a transparent stdio
proxy sitting in the middle.

**Why the engine is decoupled from MCP:** `Action { verb, resource, context }`
and `Decision { verdict, reason, risk, rule }` in [`src/core`](src/core) know
nothing about JSON-RPC. `src/adapters/mcp` is the *only* MCP-aware code — it
translates `tools/call` requests into `Action` objects. A future shell
wrapper, filesystem watcher, or network adapter would produce the same
`Action` shape and reuse the identical `PolicyEngine`, unmodified:

```
                 +----------------+
MCP (built)  --->|                |
                 |                |
Shell (Phase 2)->| Policy Engine  |----> ALLOW
                 |                |----> WARN
FS (Phase 2)  -->|                |----> BLOCK
                 |                |
Net (Phase 2) -->|                |
                 +----------------+
```

## Threat model

**In scope:** an AI agent (trusted to run code, but not necessarily trusted
with unrestricted access) invoking tools through an MCP server that is
launched as a local child process over stdio. We assume the developer
controls the gateway's own policy file and the machine it runs on.

**Out of scope / explicitly not defended against:** a malicious or compromised
*MCP server binary itself* tampering with the gateway process; an agent that
bypasses the gateway entirely by talking to a server directly (the gateway
only sees traffic routed through it — this is enforced by MCP *configuration*,
not a kernel-level guarantee); symlink/TOCTOU attacks on filesystem paths;
anything happening inside the real MCP server's own process (we only see the
JSON-RPC messages crossing the wire, not what the server does internally).

## Current capabilities

- Wraps any stdio MCP server: `agentguard-gateway --policy <file> -- <command> [args...]`
- Parses every `tools/call` request, extracts the tool name and arguments
- Heuristically classifies argument values into resource types: filesystem
  path, shell command, network URL, or a known secret pattern (see
  [Limitations](#limitations) — this is deliberately heuristic, not schema-aware)
- Evaluates each resource against a YAML policy file and computes ALLOW /
  WARN / BLOCK with an explicit reason, risk level, and matched rule
- **BLOCK** requests never reach the real server — the gateway synthesizes a
  JSON-RPC error response directly, so the agent fails cleanly
- **WARN** requests are forwarded (fail-open) but logged with the reason
- Every decision is written as a structured JSONL audit record and mirrored
  to stderr in a human-readable form
- All other MCP methods (`initialize`, `tools/list`, `ping`, ...) pass
  through untouched — policy is only evaluated where there's a resource to
  evaluate

## Limitations (read before you trust this for anything real)

- **stdio transport only.** Remote MCP servers over HTTP/SSE are not
  intercepted in Phase 1.
- **Heuristic resource extraction, not schema-aware.** We don't know each MCP
  server's tool schemas ahead of time, so we guess: an argument named `path`/
  `file`/`dir`/etc., or a string that *looks* like a path, is treated as a
  filesystem resource; a string starting with a URL scheme is treated as a
  network resource; a tool whose name matches `/shell|exec|command|.../` with
  a `command`/`cmd`/`script` argument is treated as shell execution. This
  will both miss things (an oddly-named argument) and occasionally produce a
  low-signal extra match (e.g. a shell command string that happens to contain
  a `/` also gets flagged as filesystem-shaped — harmless, since it's still
  evaluated on its own merits, but visible in the audit log).
- **Secret detection is a narrow pattern match** (AWS access key IDs, PEM
  private-key headers, a generic `key=<20+ chars>` assignment shape) applied
  to outbound tool-call *arguments* only — not a general DLP engine, and it
  does not inspect tool call *responses* at all.
- **Network enforcement is best-effort and MCP-level only.** We can see a URL
  if it appears in a tool-call argument; we cannot see raw sockets the real
  MCP server process opens on its own. True network enforcement needs an
  OS-level proxy/firewall (Phase 2).
- **No path canonicalization.** Glob matching (`src/core/glob-match.js`) is
  string-based with `~` expansion against the real home directory; it does
  not resolve symlinks or relative-path traversal tricks.
- **Trusting the pipe, not the binary.** If the developer's own MCP-client
  configuration points somewhere other than this gateway, nothing here
  intercepts it — enforcement depends on the agent actually being configured
  to run through AgentGuard.

## How to run the POC

Requires Node.js 20+.

```bash
npm install
npm test        # 30 tests covering the policy engine, translation, and a real end-to-end proxy spawn
npm run demo    # spawns the real gateway + a mock MCP server through 7 ALLOW/WARN/BLOCK scenarios
```

To wrap a real MCP server:

```bash
node bin/agentguard-gateway.js \
  --policy policy/default-policy.yaml \
  --server-name filesystem \
  -- npx -y @modelcontextprotocol/server-filesystem /path/to/workspace
```

Then point your agent's MCP client configuration at this command instead of
the real server directly (e.g. in Claude Desktop's `claude_desktop_config.json`,
replace the server's `command`/`args` with the `agentguard-gateway` invocation
above).

## Configuring policies

Policy is a YAML file with five sections (see
[`policy/default-policy.yaml`](policy/default-policy.yaml) for the full
annotated reference, and [`src/core/policy-engine.js`](src/core/policy-engine.js)
`applyDefaults()` for exact defaults):

```yaml
filesystem:
  allow: []      # optional; if non-empty, anything outside it -> WARN
  deny: []       # -> BLOCK, risk CRITICAL
  warn: []       # -> WARN, risk MEDIUM

shell:
  allowed: []    # binaries allowed via a shell-style MCP tool; empty = block all

mcp:
  allowed_servers: []   # empty = trust all servers (no reputation data yet)

network:
  allowed_domains: []   # empty = no restriction (best-effort visibility only)

secrets:
  block_exfiltration: true
```

**Documented default-policy decisions** (deliberate, not arbitrary):

| Action | Verdict | Why |
|---|---|---|
| Read `~/.ssh/**`, `~/.aws/**`, `~/.kube/**`, `*.pem`, etc. | **BLOCK** (CRITICAL) | No legitimate agent workflow needs raw credential material. |
| Read `.env`, `.env.*` | **WARN** (MEDIUM) | Often legitimately read by build tooling/tests; a hard block breaks normal dev workflows, so we surface it instead of blocking it. |
| Invoke a server not in `mcp.allowed_servers` | **WARN**, or **ALLOW** if the list is empty | Phase 1 has no server-reputation data; empty list = trust everything configured, non-empty = explicit allowlist. |
| Shell-style tool call with a command not in `shell.allowed` | **BLOCK** (HIGH) | Arbitrary shell execution is the highest-leverage action an agent can take; deny-by-default here, unlike filesystem. |
| A tool-call argument matching a known secret pattern | **BLOCK** (CRITICAL) | Credential material should never be an argument to any tool call. |

## Example security events

```
[ALLOW] MCP request received
[ALLOW] Tool: read_file
[ALLOW] Target: mcp-server:trusted-server, filesystem:./src/auth.js
[ALLOW] Policy decision: ALLOW
```

```
[BLOCK] MCP request received
[BLOCK] Tool: read_file
[BLOCK] Target: mcp-server:trusted-server, filesystem:~/.aws/credentials
[BLOCK] Policy decision: BLOCK
[BLOCK] Reason: Path matches a denied pattern in filesystem.deny ("~/.aws/**"); credential/sensitive paths are not accessible to agents.
```

The matching JSONL audit record (`--log <file>`) carries the same
information structured for machine consumption, including every individual
sub-decision that fed into the final verdict:

```json
{"timestamp":"2026-09-02T10:00:00.000Z","sessionId":"…","source":"mcp","serverName":"trusted-server","method":"tools/call","toolName":"read_file","resource":"mcp-server:trusted-server, filesystem:~/.aws/credentials","decision":"BLOCK","risk":"CRITICAL","rule":"filesystem.deny","reason":"…","subDecisions":[{"resourceType":"mcp-server","value":"trusted-server","verdict":"ALLOW","rule":"mcp.allowed_servers"},{"resourceType":"filesystem","value":"~/.aws/credentials","verdict":"BLOCK","rule":"filesystem.deny"}]}
```

## Project layout

```
bin/agentguard-gateway.js     CLI entrypoint (arg parsing, policy loading)
src/core/                     transport-agnostic: Action, Decision, PolicyEngine, AuditLogger, glob matching
src/adapters/mcp/             MCP-specific: JSON-RPC translation + the stdio proxy
policy/default-policy.yaml    shipped reference policy
examples/                     runnable demo (run-demo.mjs) + its policy
test/                         unit tests (policy engine, translation, glob matching) + one real end-to-end proxy test
```

## Phase 2

Not built, and intentionally not attempted here:

- **Posture scanner** (`agentguard scan`): detect installed agent runtimes,
  network-exposed local AI services, sensitive-path accessibility, and
  produce a security-posture score. Needs its own host-inspection data model
  before any scoring is meaningful — explicitly deferred rather than shipping
  a superficial score.
- **Shell and filesystem adapters** that feed the same `PolicyEngine` for
  actions taken outside MCP entirely.
- **Real network enforcement** via an OS-level proxy, rather than best-effort
  URL-argument inspection.
- **HTTP/SSE MCP transport** support.
- **Response inspection** (catching secrets flowing back to the agent, not
  just outbound in arguments).
- Anomaly detection, LLM-assisted risk evaluation, dashboards — all
  explicitly deferred; Phase 1 stays deterministic and explainable.
