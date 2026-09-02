# AgentGuard — Local AI Agent Security Gateway (Phase 1 + 2 POC)

> **This is a DevDay proof-of-concept, not a production EDR or a complete AI
> security platform.** It demonstrates a real, working security control: a
> local posture scanner that discovers what AI/agent software and exposure
> exist on a developer machine, and a real MCP stdio proxy that intercepts
> tool calls, evaluates them against a deterministic policy, and enforces
> ALLOW/WARN/BLOCK at runtime. Everything still out of scope — full EDR,
> anomaly/ML detection, a web dashboard, kernel-level monitoring — is listed
> honestly in [Limitations](#limitations) and [Phase 3](#phase-3).

## The problem

Developers install local AI agent tooling (agent harnesses, MCP servers,
local model runtimes) on the same machines that hold source code, `.env`
files, SSH keys, and cloud credentials. A vulnerability scanner can tell you
the *software* is configured insecurely; it cannot tell you **what the agent
can access, and what it actually did at runtime** — did it read
`~/.ssh/id_rsa`? Did it shell out to `curl`? Is a local model server
listening on every interface instead of just localhost? That is the question
AgentGuard answers, in two complementary layers:

- **Layer 1 — Local AI Security Posture** (`agentguard scan`): DISCOVER what
  AI/agent software, MCP servers, exposed services, and sensitive resources
  exist on this machine, and ASSESS the risk that combination represents —
  *before* an agent runs.
- **Layer 2 — Runtime Agent Security** (`agentguard gateway`): OBSERVE what
  an agent is trying to do through MCP, EVALUATE it against policy, and
  ENFORCE ALLOW/WARN/BLOCK, with every decision AUDITed — *while* an agent
  runs.

We are not attempting to classify "malicious AI" or infer intent — nothing
here claims to know *why* an agent did something. We model **capabilities,
resources, actions, policies, risk, and violations**, and enforce
deterministic, explainable rules against them:

```
Agent
  |
  +--> Action: READ
  |
  +--> Resource: ~/.aws/credentials
  |
  +--> Policy: filesystem.deny
  |
  +--> Risk: CRITICAL
  |
  +--> Decision: BLOCK
```

The product narrative this POC demonstrates end-to-end (`npm run demo`):
**"Before the agent starts, we assess its security posture. While it runs,
we enforce what it is allowed to do."**

## Architecture

```
                                 Developer Machine
┌──────────────────────────────────────────────────────────────────────┐
│                                                                       │
│  AI Agent / Harness (Claude Code, Claude Desktop, etc.)              │
│             │ spawns, over stdio, as its configured "MCP server"     │
│             ▼                                                       │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │                  AgentGuard Gateway                      │        │
│  │                                                          │        │
│  │  MCP adapter (src/adapters/mcp)                          │        │
│  │    tools/call JSON-RPC  --->  generic Action[]            │        │
│  │                                                          │        │
│  │  Policy Engine  --->  sensitivity  --->  Risk Engine       │        │
│  │    Action  --->  Decision {ALLOW | WARN | BLOCK, risk}     │        │
│  │                                                          │        │
│  │  SecurityEvent + Audit Logger                            │        │
│  │    every decision -> JSONL (the event store) + stderr    │        │
│  └──────────────────────┬────────────────────────────────────┘        │
│             │ spawns, over stdio, the real command                   │
│             ▼                                                       │
│  Real MCP Server (e.g. @modelcontextprotocol/server-filesystem)      │
│                                                                       │
│  ┌─────────────────────────────────────────────────────────┐        │
│  │             Local Posture Scanner (agentguard scan)      │        │
│  │                                                          │        │
│  │  src/adapters/discovery/  (uses src/adapters/host/ OS    │        │
│  │    agent-detection          primitives: process list,    │        │
│  │    mcp-config                listening ports, PATH       │        │
│  │    network-exposure           lookup — read-only,        │        │
│  │    sensitive-resources        fixed-arg execFile calls)  │        │
│  │             │                                            │        │
│  │             ▼                                            │        │
│  │  findings-rules.js  --->  SecurityFinding[]                │        │
│  │             │                                            │        │
│  │             ▼                                            │        │
│  │  SecurityPosture (findings, severity counts, score)      │        │
│  └─────────────────────────────────────────────────────────┘        │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

The gateway is itself an MCP "server" from the agent's point of view, and an
MCP "client" from the real server's point of view — a transparent stdio
proxy sitting in the middle. The scanner is a separate, independent
read-only pass over the host; it does not need the gateway to be running,
and the gateway does not need a scan to have been run.

**Why the core is decoupled from MCP:** `Action`, `Decision`, `PolicyEngine`,
`RiskEngine`, `SecurityEvent`, `SecurityFinding`, and `SecurityPosture` in
[`src/core`](src/core) know nothing about JSON-RPC or MCP. `src/adapters/mcp`
is the *only* MCP-aware code for the runtime side, and `src/adapters/host` +
`src/adapters/discovery` are the *only* OS-aware code for the posture side.
A future shell wrapper or filesystem watcher would produce the same `Action`
shape and reuse the identical `PolicyEngine`/`RiskEngine`, unmodified:

```
                 +----------------+
MCP (built)  --->|                |
                 |                |
Shell (Phase 3)->| Policy Engine  |--->| Risk Engine |---> ALLOW
                 |                |                  ---> WARN
FS   (Phase 3)-->|                |                  ---> BLOCK
                 |                |
Net  (Phase 3)-->|                |
                 +----------------+
```

## Risk model

`PolicyEngine` computes a resource **sensitivity** (how dangerous this kind
of resource inherently is) while it evaluates a rule; `RiskEngine`
(`src/core/risk-engine.js`) turns that plus the verdict into the risk level
actually reported — one function, not a literal re-typed at every policy
branch:

- a credential-pattern match always forces **CRITICAL**, regardless of
  anything else
- **BLOCK** is never reported below **HIGH** — a denied action is
  inherently risky even when its specific resource's baseline sensitivity is
  lower
- **WARN** is never reported below **MEDIUM**
- **ALLOW** reports the resource's own sensitivity, with a **LOW** floor —
  every observed action carries some baseline risk simply by being an action

| Example | Verdict | Risk |
|---|---|---|
| `read ./src/auth.ts` | ALLOW | LOW |
| `read .env` | WARN | HIGH |
| `read ~/.aws/credentials` | BLOCK | CRITICAL |
| `invoke trusted MCP tool` | ALLOW | LOW |
| `invoke unknown MCP server` | WARN | MEDIUM |

(These are exercised exactly as written in [`test/risk-engine.test.js`](test/risk-engine.test.js).)

## Event correlation

Every evaluated action becomes a `SecurityEvent` (`src/core/security-event.js`),
written to the gateway's JSONL audit log — **the audit log is the event
store**; no separate database was added for a POC. `agentguard events` reads
it back and groups by `sessionId`, answering "what did this agent do during
this session?" One gateway connection = one session. There is no identity
signal beyond that yet: `agentId` currently equals `sessionId` (documented
limitation — see below). This is the foundation for correlation (e.g. a
`.env` read followed by a network call in the same session), not
correlation logic itself — deliberately, per the brief: we are not building
DLP or exfiltration detection in this phase.

## Threat model

**In scope:** an AI agent (trusted to run code, but not necessarily trusted
with unrestricted access) invoking tools through an MCP server launched as a
local child process over stdio, on a machine the developer controls the
gateway's policy file and host access for.

1. **Prompt injection** — malicious content manipulates the agent into
   attempting an unintended sensitive action. AgentGuard does not detect the
   injection itself (it cannot see the agent's reasoning), but it blocks the
   *resulting* tool call the same as any other policy violation — the
   defense is at the action boundary, not the input.
2. **Malicious/untrusted MCP server** — `mcp.allowed_servers` plus
   `agentguard scan`'s MCP discovery flag any server not explicitly trusted.
3. **Credential exposure** — `filesystem.deny`/`warn` block/flag credential
   paths at runtime; `agentguard scan`'s sensitive-resource check flags their
   mere presence as a standing exposure, before any agent even runs.
4. **Excessive filesystem access** — `filesystem.allow` scopes an agent to a
   workspace; anything outside it WARNs.
5. **Unexpected network access** — best-effort only (see Limitations):
   `network.allowed_domains` catches a URL visible in a tool-call argument,
   nothing more.
6. **Agent misconfiguration** — `agentguard scan` surfaces a service bound
   to `0.0.0.0` instead of localhost, or a workspace with `.env`/credentials
   sitting where a misconfigured agent could reach them.

**Out of scope / explicitly not defended against:** a malicious or
compromised *MCP server binary itself* tampering with the gateway process;
an agent that bypasses the gateway entirely by talking to a server directly
(enforced by MCP *configuration*, not a kernel-level guarantee);
symlink/TOCTOU attacks on filesystem paths; anything happening inside the
real MCP server's own process; true model intent (we observe actions, never
reasoning).

## Current capabilities

**Runtime gateway:**
- Wraps any stdio MCP server: `agentguard gateway --policy <file> -- <command> [args...]`
- Parses every `tools/call` request, extracts the tool name and arguments,
  heuristically classifies argument values into resource types (filesystem,
  shell, network, secret — see [Limitations](#limitations))
- Tags each action with an `ActionType` (`MCP_TOOL_CALL`, `FILE_READ`,
  `FILE_WRITE`, `SHELL_EXEC`, `NETWORK_REQUEST`, `SECRET_PATTERN_MATCH`) —
  only types something in `src/adapters` actually produces; `FILE_WRITE` is
  a tool-name heuristic (`write_file`, `create_*`, etc.), defaulting to read
- Evaluates each resource against a YAML policy and computes ALLOW/WARN/BLOCK
  with an explicit reason, a `RiskEngine`-derived risk level, and matched rule
- **BLOCK** requests never reach the real server — a synthesized JSON-RPC
  error (with `risk`/`rule`/`eventId` in its `data` field) goes straight back
- **WARN** requests are forwarded (fail-open) but logged with the reason
- Every decision becomes a `SecurityEvent`, written as JSONL and mirrored to
  stderr

**Posture scanner (`agentguard scan`):**
- Detects known local AI/agent runtimes (Ollama, Claude Code, OpenClaw,
  Hermes) via running processes and PATH lookups — read-only, fixed-arg
  `execFile` calls only, no shell interpolation, no elevated privileges
- Discovers MCP client configurations (`.mcp.json`, Claude Code/Desktop
  configs) and cross-references server names against the gateway policy's
  `mcp.allowed_servers` for a trust label — **parses JSON only, never
  executes a discovered command**
- Checks this machine's own listening-socket table for a detected agent's
  known default port bound beyond localhost (e.g. Ollama on `0.0.0.0:11434`)
  — self-inspection only, never opens an outbound connection
- Checks **existence and permissions only** (never contents) of sensitive
  paths (`~/.ssh`, `~/.aws`, `~/.config/gcloud`, `~/.kube`, `.env`,
  `credentials.json`, `secrets.yaml`)
- Produces a `SecurityPosture`: findings with id/title/severity/category/
  description/evidence/recommendation, severity counts, an indicative 0–100
  score, and an overall risk label

**`agentguard events`** reads the gateway's JSONL audit log and prints a
per-session, time-ordered view of what an agent did.

## Limitations (read before you trust this for anything real)

**Runtime gateway:**
- **stdio transport only.** Remote MCP servers over HTTP/SSE are not
  intercepted.
- **Heuristic resource extraction, not schema-aware.** We don't know each
  MCP server's tool schemas ahead of time, so path/shell/network/write-vs-read
  classification is all name- and shape-based guessing. This both misses
  things (an oddly-named argument) and occasionally produces a low-signal
  extra match (e.g. a shell command string containing a URL also gets
  flagged as filesystem-shaped — harmless, evaluated on its own merits, just
  visible in the audit log).
- **Secret detection is a narrow pattern match** (AWS access key IDs, PEM
  private-key headers, a generic `key=<20+ chars>` assignment) applied to
  outbound tool-call *arguments* only — not a general DLP engine, and it
  does not inspect tool call *responses* at all.
- **Network enforcement is best-effort and MCP-level only.** We can see a
  URL if it appears in a tool-call argument; we cannot see raw sockets the
  real MCP server process opens on its own.
- **No path canonicalization.** Glob matching is string-based with `~`
  expansion against the real home directory; no symlink resolution.
- **Trusting the pipe, not the binary.** Enforcement depends on the agent
  actually being configured to run through AgentGuard.
- **`agentId` === `sessionId`.** There is no identity signal beyond one
  gateway connection yet, so correlating the *same agent* across multiple
  gateway runs isn't possible today.

**Posture scanner:**
- **Process/PATH detection is a small, hand-maintained registry**
  (`src/adapters/discovery/known-agents.js`) of publicly-known names — it
  will miss anything not in that table, and a process merely *named*
  similarly to a known agent produces a false positive. Absence from a scan
  means "not checked for", never "confirmed absent".
- **MCP config discovery checks a fixed, non-exhaustive list of common
  locations** and does not scan the filesystem for arbitrary config files.
- **Network exposure checking depends on OS tooling being present and
  permitted** (`netstat` on Windows; `lsof` on POSIX — if `lsof` isn't
  installed, POSIX network-exposure detection silently returns nothing
  rather than failing the scan; this is a documented degrade, not a bug).
  It is explicitly *not* a port scanner: only ports belonging to an already
  *detected* agent are considered, and it never opens a connection anywhere.
- **The 0–100 score is a simple, fixed per-severity deduction — indicative,
  not a calibrated risk model.** Read the severity counts, not the number,
  as the primary signal.
- **A local scanner is not a replacement for EDR.** It cannot see every
  OS-level action, does not run continuously, and does not guarantee
  detection or prevention of data exfiltration.
- **Nothing here overclaims intent or malice.** A finding means "this
  configuration/exposure exists", never "this agent is malicious."

## How to run the POC

Requires Node.js 20+.

```bash
npm install
npm test        # 73 tests: policy/risk engine, translation, discovery (all with fake data sources), and real end-to-end proxy + CLI spawns
npm run demo    # the full narrative: agentguard scan -> gateway enforces 7 ALLOW/WARN/BLOCK scenarios -> agentguard events
npm run scan    # agentguard scan against THIS machine
```

To wrap a real MCP server:

```bash
node bin/agentguard.js gateway \
  --policy policy/default-policy.yaml \
  --log audit.jsonl \
  --server-name filesystem \
  -- npx -y @modelcontextprotocol/server-filesystem /path/to/workspace
```

Then point your agent's MCP client configuration at this command instead of
the real server directly (e.g. in Claude Desktop's `claude_desktop_config.json`,
replace the server's `command`/`args` with the invocation above). The
standalone `bin/agentguard-gateway.js` still works identically, unchanged,
for the same purpose — `agentguard gateway` and `agentguard-gateway` call
the exact same underlying command.

To review what an agent did afterward:

```bash
node bin/agentguard.js events --log audit.jsonl [--session <sessionId>]
```

## Configuring policies

Policy is a YAML file with five sections (see
[`policy/default-policy.yaml`](policy/default-policy.yaml) for the full
annotated reference, and `applyDefaults()` in
[`src/core/policy-engine.js`](src/core/policy-engine.js) for exact defaults):

```yaml
filesystem:
  allow: []      # optional; if non-empty, anything outside it -> WARN
  deny: []       # -> BLOCK
  warn: []       # -> WARN

shell:
  allowed: []    # binaries allowed via a shell-style MCP tool; empty = block all

mcp:
  allowed_servers: []   # empty = trust all servers (no reputation data yet);
                         # also used by `agentguard scan` to label MCP trust

network:
  allowed_domains: []   # empty = no restriction (best-effort visibility only)

secrets:
  block_exfiltration: true
```

**Documented default-policy decisions** (deliberate, not arbitrary):

| Action | Verdict | Risk | Why |
|---|---|---|---|
| Read `~/.ssh/**`, `~/.aws/**`, `~/.kube/**`, `*.pem`, etc. | **BLOCK** | CRITICAL | No legitimate agent workflow needs raw credential material. |
| Read `.env`, `.env.*` | **WARN** | HIGH | Often legitimately read by build tooling/tests; a hard block breaks normal dev workflows, so we surface it with real weight instead of silently allowing it. |
| Invoke a server not in `mcp.allowed_servers` | **WARN** (or ALLOW if the list is empty) | MEDIUM | Phase 1/2 has no server-reputation data; empty list = trust everything configured, non-empty = explicit allowlist. |
| Shell-style tool call with a command not in `shell.allowed` | **BLOCK** | HIGH | Arbitrary shell execution is the highest-leverage action an agent can take; deny-by-default here, unlike filesystem. |
| A tool-call argument matching a known secret pattern | **BLOCK** | CRITICAL | Credential material should never be an argument to any tool call. |

`ActionType` (`src/core/action.js`) intentionally only lists action shapes
something in `src/adapters` actually produces today — `SHELL_EXEC` is real
(the MCP adapter observes shell-style tool calls), but there is no
independent, non-MCP shell-execution *event source* yet. Adding one is
Phase 3 work; the abstraction (`ActionType`, `Action`, `PolicyEngine`) is
already shaped to receive it without modification.

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

The matching JSONL `SecurityEvent` (`--log <file>`) carries the same
information structured for machine consumption:

```json
{"id":"…","sessionId":"…","agentId":"…","timestamp":"2026-09-02T10:00:00.000Z","source":"mcp","actionType":"FILE_READ","toolName":"read_file","serverName":"trusted-server","resource":"mcp-server:trusted-server, filesystem:~/.aws/credentials","decision":"BLOCK","risk":"CRITICAL","rule":"filesystem.deny","reason":"…","subDecisions":[{"resourceType":"mcp-server","value":"trusted-server","verdict":"ALLOW","rule":"mcp.allowed_servers"},{"resourceType":"filesystem","value":"~/.aws/credentials","verdict":"BLOCK","rule":"filesystem.deny"}]}
```

And an example `SecurityFinding` from `agentguard scan`:

```json
{
  "id": "NETWORK-001",
  "title": "Ollama exposed beyond localhost",
  "severity": "HIGH",
  "category": "network",
  "description": "Ollama is listening on an address other than localhost, making it potentially reachable from other machines on the network.",
  "evidence": "Ollama listening on 0.0.0.0:11434",
  "recommendation": "Bind the service to localhost (127.0.0.1) unless remote access is explicitly required."
}
```

## Project layout

```
bin/agentguard.js             umbrella CLI: gateway | scan | events
bin/agentguard-gateway.js     standalone gateway CLI (unchanged behavior, now a thin wrapper)

src/core/                     transport-agnostic: Action, ActionType, Decision, PolicyEngine,
                                 RiskEngine, SecurityEvent, SecurityFinding, SecurityPosture,
                                 findings-rules, AuditLogger, glob matching

src/adapters/mcp/             MCP-specific: JSON-RPC translation + the stdio proxy
src/adapters/host/            OS primitives: process list, listening ports, PATH lookup
src/adapters/discovery/       agent detection, MCP config discovery, network exposure,
                                 sensitive-resource scan, and the scan orchestrator

src/cli/                      gateway-command, scan-command, events-command (shared by both bins)

policy/default-policy.yaml    shipped reference policy
examples/                     runnable demo (scan -> gateway -> events) + its policy
test/                         unit tests (dependency-injected, no reliance on host state) +
                                 real end-to-end proxy/CLI spawns + a live scan of the actual host
```

## Phase 3

Not built, and intentionally not attempted here — see the brief's own
explicit "do not build yet" list (LLM-based intent detection, ML anomaly
detection, full EDR, kernel-level monitoring, packet inspection, a cloud
backend, auth/SSO, Kubernetes, a complex dashboard, automated remediation,
automatic secret rotation). Concretely next, in rough priority order:

- **Shell and filesystem adapters** that produce real (non-MCP) `Action`s
  and feed the same `PolicyEngine`/`RiskEngine` — the abstraction exists,
  the event sources don't yet.
- **Real network enforcement** via an OS-level proxy, rather than
  best-effort URL-argument inspection.
- **HTTP/SSE MCP transport** support.
- **Response inspection** (catching secrets flowing back to the agent, not
  just outbound in arguments).
- **Actual event correlation logic** on top of the foundation now in place
  (e.g. flagging a `.env` read followed by an external network call in the
  same session) — explicitly *not* full DLP, just pattern-of-events rules.
- **A real agent identity** distinct from `sessionId`, so the same agent's
  behavior can be tracked across multiple gateway runs.
- Anomaly detection, LLM-assisted risk evaluation, a dashboard — all still
  deliberately deferred; this stays deterministic and explainable.
