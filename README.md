# AgentGuard — Local AI Agent Security Gateway (DevDay POC)

> **This is a DevDay proof-of-concept, not a production EDR or a complete AI
> security platform.** It demonstrates a real, working security control: a
> local posture scanner, an MCP stdio proxy that enforces policy at runtime,
> a shell-command wrapper that enforces policy on non-MCP commands, and a
> deterministic correlation engine that flags risky *patterns* of behavior
> across a session. Everything still out of scope — full EDR, anomaly/ML
> detection, a web dashboard, kernel-level monitoring — is listed honestly in
> [Limitations](#limitations) and [Future Work](#future-work).
>
> **This project has been red-teamed against its own claims, not just unit
> tested.** [SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md) documents nine
> real bypasses found and reproduced with automated exploits, eight fully
> fixed (with permanent regression tests) and one narrowed with the residual
> gap stated plainly rather than glossed over. Read it before trusting any
> claim in this README.

**What is it?** A lightweight runtime security gateway for AI agents
running on developer machines.

**Why does it exist?** AI agents increasingly have access to source code,
credentials, MCP tools, and local system capabilities — the same trust
traditional AppSec already knows how to reason about, just applied to a
new kind of caller:

```
Traditional application security:          Agent security:

User                                        Agent
 ↓                                           ↓
Application                                 Tools / MCP / local capabilities
 ↓                                           ↓
Security Controls                           Security Controls
```

**What does it do?** DISCOVER what's on the machine → ASSESS the risk that
represents → OBSERVE what an agent actually does → EVALUATE it against
policy → ENFORCE the boundary (before the action happens, not after) →
CORRELATE the sequence → EXPLAIN the decision. Least privilege, policy
enforcement, risk assessment, input inspection, runtime controls,
auditability — applied to agent activity instead of application traffic.

**How do I see it?**
```bash
npm install
npm run demo
```
That's the whole setup — no external services, no real credentials, safe
to run repeatedly. See [docs/DEV-DAY-DEMO.md](docs/DEV-DAY-DEMO.md) for a
narrated walkthrough and [docs/architecture.md](docs/architecture.md) for
the diagram.

**AgentGuard is not an AI detector.** It doesn't try to determine whether
an agent is malicious — it establishes explicit boundaries around what an
agent is allowed to do, and enforces them.

## The problem

Developers install local AI agent tooling (agent harnesses, MCP servers,
local model runtimes) on the same machines that hold source code, `.env`
files, SSH keys, and cloud credentials. A vulnerability scanner can tell you
the *software* is configured insecurely; it cannot tell you **what the agent
can access, and what it actually did at runtime** — did it read
`~/.ssh/id_rsa`? Did it shell out to `curl`? Did a "helpful" tool response
quietly try to redirect it? That is the question AgentGuard answers.

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
**"We don't decide whether the AI is good or evil. We define what an AI
agent is allowed to do, observe what it actually does, and enforce that
boundary at runtime."**

## Posture vs. Runtime vs. Correlation

Three deliberately separate concepts, never merged into one meaningless
number:

| | Answers | Produced by |
|---|---|---|
| **Posture** | "What *could* happen?" — before any agent runs | `agentguard scan` → `SecurityPosture` (findings, severity counts, indicative score) |
| **Runtime** | "What *actually* happened?" — while an agent runs | `agentguard gateway` / `agentguard exec` → `SecurityEvent`s (ALLOW/WARN/BLOCK + risk, per action) |
| **Correlation** | "Does the *sequence* of what happened indicate a risky pattern?" | `agentguard events` → `Detection`s (a behavioral pattern match, not proof of anything) |

A posture score and a runtime event count are answering different
questions and are never combined. A `Detection` is a third, separate thing
again: it says a *sequence* of already-evaluated events looks like a known
risky pattern — it does not re-judge any individual event, and it is not
evidence of compromise, just a pattern worth a human looking at.

## Architecture

```
                                 Developer Machine
┌───────────────────────────────────────────────────────────────────────────┐
│                                                                           │
│  AI Agent / Harness (Claude Code, Claude Desktop, etc.)                  │
│     │ MCP: spawns, over stdio, as its configured "MCP server"            │
│     │ Shell: routed through `agentguard exec` instead of running direct  │
│     ▼                                     ▼                              │
│  ┌─────────────────────────────┐   ┌──────────────────────────────┐      │
│  │      AgentGuard Gateway      │   │      agentguard exec          │      │
│  │                              │   │                              │      │
│  │  MCP adapter                 │   │  argv --> Action[]            │      │
│  │    tools/call --> Action[]    │   │  (real, already-split argv,   │      │
│  │  Response inspector           │   │   not a guessed string)       │      │
│  │    result --> findings         │   │                              │      │
│  │                              │   │  BLOCK => never spawn()        │      │
│  │  clientInfo --> agentId        │   └──────────────┬───────────────┘      │
│  │                              │                  │                     │
│  │  Policy Engine --> sensitivity │                  │                     │
│  │       --> Risk Engine          │◄─────────────────┘  (same engine,       │
│  │  Action --> Decision            │                      same core)        │
│  │    {ALLOW|WARN|BLOCK, risk}    │                                       │
│  │                              │                                       │
│  │  SecurityEvent + AuditLogger  │                                       │
│  │    every decision -> JSONL    │                                       │
│  └──────────────┬────────────────┘                                       │
│     │ spawns, over stdio, the real command                               │
│     ▼                                                                   │
│  Real MCP Server                                                        │
│                                                                           │
│  ┌────────────────────────────┐   ┌──────────────────────────────┐      │
│  │  Local Posture Scanner       │   │  agentguard events            │      │
│  │  (agentguard scan)           │   │                              │      │
│  │  src/adapters/discovery/     │   │  JSONL --> grouped by session  │      │
│  │  --> SecurityFinding[]        │   │  --> Correlation Engine        │      │
│  │  --> SecurityPosture          │   │      (deterministic sequence  │      │
│  │      (score, severity counts)│   │       rules) --> Detection[]   │      │
│  └────────────────────────────┘   └──────────────────────────────┘      │
│                                                                           │
└───────────────────────────────────────────────────────────────────────────┘
```

The gateway is itself an MCP "server" from the agent's point of view, and an
MCP "client" from the real server's point of view. `agentguard exec` is the
same pattern applied to a directly-run command: AgentGuard is the one that
calls `spawn()`, so on BLOCK it simply never does. Both are **enforcement
boundaries for whatever is actually routed through them** — see
[Limitations](#limitations).

**Why the core stays decoupled from any one adapter:** `Action`, `Decision`,
`PolicyEngine`, `RiskEngine`, `SecurityEvent`, `SecurityFinding`,
`SecurityPosture`, `Detection` in [`src/core`](src/core) know nothing about
MCP, stdio, or shells. `src/adapters/mcp` and `src/adapters/shell` are two
independent, real proof points of that design — both produce the same
`Action` shape and are evaluated by the identical `PolicyEngine`/`RiskEngine`,
unmodified:

```
                 +----------------+
MCP (built)  --->|                |
                 |                |
Shell (built)--->| Policy Engine  |--->| Risk Engine |---> ALLOW
                 |                |                  ---> WARN
FS  (Phase 4) -->|                |                  ---> BLOCK
                 |                |
Net (Phase 4) -->|                |
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
- **BLOCK** is never reported below **HIGH**
- **WARN** is never reported below **MEDIUM**
- **ALLOW** reports the resource's own sensitivity, with a **LOW** floor

| Example | Verdict | Risk |
|---|---|---|
| `read ./src/auth.ts` | ALLOW | LOW |
| `read .env` | WARN | HIGH |
| `read ~/.aws/credentials` | BLOCK | CRITICAL |
| `invoke trusted MCP tool` | ALLOW | LOW |
| `invoke unknown MCP server` | WARN | MEDIUM |

(Exercised exactly as written in [`test/risk-engine.test.js`](test/risk-engine.test.js).)

## Runtime enforcement: MCP gateway + `agentguard exec`

**MCP gateway** (Phase 1/2, unchanged): wraps a stdio MCP server, evaluates
every `tools/call`, blocks by never forwarding, warns by forwarding-and-logging.

**`agentguard exec --policy <file> [--log <file>] -- <command> [args...]`**
(new in Phase 3): evaluates `command args...` against the *same* policy
**before ever calling `spawn()`**. On BLOCK, the process is never created —
this is genuine prevention, not after-the-fact observation, for anything
routed through it. Unlike the MCP adapter, which has to guess resource
shapes out of a joined command string or unknown JSON keys, `agentguard exec`
gets real, already-split `argv`: the binary is unambiguous, and each
argument is checked on its own merits (so `agentguard exec -- npm pack
~/.ssh/id_rsa` is BLOCKed by `filesystem.deny` even though `npm` itself is
allowed).

**IMPORTANT — read this before treating either as a general interceptor:**
both are enforcement boundaries for commands *actually routed through them*,
exactly like a firewall only sees traffic sent to it. A command run directly
by the agent, bypassing `agentguard exec`, or an MCP call made outside the
gateway's stdio pipe, is invisible to AgentGuard. Neither is EDR, and neither
claims host-level visibility.

`shell.deny` (new) is checked *before* `shell.allowed` and always wins, even
for a binary also present in `allowed` — a second layer for commands that
should never run regardless of what else is permitted.

## MCP response inspection

The gateway now inspects the **response** to every forwarded `tools/call`,
not just the request (`src/adapters/mcp/response-inspect.js`). Deterministic
pattern checks only — this is a detection signal, never proof of anything:

- the same secret patterns used on the request side, now applied to response
  content (`mcp_response_inspection.block_on_secret_pattern`, **default
  true** — mirrors the request-side default)
- a narrow, high-false-negative instruction-injection pattern list ("ignore
  previous instructions", etc.) — `block_on_suspicious_instruction`,
  **default false** (log/WARN only; blocking on a keyword match alone is
  opt-in, per design)

A response is only logged as its own `SecurityEvent` (`direction: "response"`)
when something was actually found — the overwhelmingly common clean-response
case isn't double-logged. A BLOCKed response never reaches the agent; a
synthesized JSON-RPC error replaces it, same mechanism as a request-side
BLOCK.

## Identity

`agentId` is now captured from the MCP `initialize` handshake's
`clientInfo.name` — the one piece of real identity signal the protocol
actually provides — instead of always defaulting to `sessionId`. If a client
never sends `clientInfo` (or this is an `agentguard exec` run, which has no
MCP handshake at all), `agentId` falls back to `sessionId`, documented, not
invented. **Nothing stops a client from sending a false `clientInfo.name`** —
this is the strongest signal available, not an authenticated identity.
`sessionId` (one connection/run) and `serverName`/`toolName` (one MCP
connection / one tool) remain distinct concepts, as before.

## Event correlation

Every evaluated action becomes a `SecurityEvent`, written to the JSONL audit
log — **the audit log is the event store**, no separate database. `agentguard
events` groups it by `sessionId` and now also runs the **correlation engine**
(`src/core/correlation-engine.js`) against each session's full, time-ordered
event list. Four deterministic, ordered-sequence rules — no ML, no scoring
model, just "does pattern A appear before pattern B (before C)":

| Rule | Pattern | Severity |
|---|---|---|
| Sensitive read → network | HIGH+ risk `FILE_READ` followed by any `NETWORK_REQUEST` | HIGH |
| Credential access → shell | CRITICAL `FILE_READ` (ssh/aws-level) followed by `SHELL_EXEC` | CRITICAL |
| Untrusted server → sensitive read | untrusted-MCP-server WARN followed by a HIGH+ `FILE_READ` | HIGH |
| Escalation pattern | untrusted server → sensitive read → network, all three in order | CRITICAL |

Each rule reports at most one `Detection` per session (not every recurrence)
to keep output readable, and rules are **not mutually exclusive** —
overlapping evidence can trigger more than one, and that's shown, not
deduplicated away. Correlation is deliberately scoped to **one session's own
events**: it does not span across a gateway session and a separate
`agentguard exec` run (see Identity/Limitations — `sessionId` doesn't persist
across adapters today), and it says nothing about intent — see
[Posture vs. Runtime vs. Correlation](#posture-vs-runtime-vs-correlation).

## Threat model

**In scope:** an AI agent (trusted to run code, but not necessarily trusted
with unrestricted access) invoking tools through an MCP server over stdio,
and/or running shell commands routed through `agentguard exec`, on a machine
the developer controls the policy file and host access for.

**Is AgentGuard a mandatory boundary the agent cannot route around?** No —
this was explicitly re-verified in [SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md)
rather than assumed. Neither the gateway nor `agentguard exec` is a kernel-
level chokepoint: an agent whose MCP client config points at the real server
directly, or a command run without going through `agentguard exec`, is
invisible to AgentGuard. This is inherent to a userspace proxy architecture,
the same way a corporate HTTP proxy only sees traffic actually sent to it —
not a gap introduced by an implementation shortcut, and not something this
project claims to solve.

**Asset-by-asset summary** (full detail in the numbered list below and in
[SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md)):

| Asset | Threat | Attack path | AgentGuard control | Residual risk |
|---|---|---|---|---|
| Source code / repos | Excessive read/write access | Agent reads/writes outside its intended workspace | `filesystem.allow` scoping (both adapters) | No symlink resolution; a workspace escape via a symlink isn't caught |
| Credentials (SSH keys, `.env`, cloud config) | Exposure or exfiltration | Agent reads a credential path, directly or via traversal | `filesystem.deny`/`warn` + traversal collapsing (F4) + `agentguard scan` standing-exposure check | Still lexical matching, not full canonicalization |
| MCP servers | Untrusted/malicious server | An unlisted or spoofable server is invoked | `mcp.allowed_servers` + posture discovery + response inspection | `serverName` has no cryptographic binding to what's actually spawned — an operator-trust question |
| Developer workstation (shell) | Dangerous/arbitrary execution | A denied command, or an allowed interpreter given arbitrary code via `-e`/`-c` | `shell.allowed`/`deny` (basename-normalized, F3) + `shell.block_interpreter_eval` (F2) | Interpreter mitigation is narrow — doesn't stop a payload written to a file first |
| External destinations | Data exfiltration | A tool call or shell command reaches an unexpected domain | `network.allowed_domains` (best-effort) + correlation (sensitive-read-then-network) | No raw socket visibility — only URLs visible in MCP arguments |
| Malicious/untrusted tool responses | Instruction injection, secret leakage in a response | A tool response contains an injected instruction or a credential | MCP response inspection (secret pattern BLOCK, instruction pattern WARN) | Pattern-based only — rephrased injection or a response shape without a `text` key evades it (F5) |
| The gateway itself (bypass) | Agent routes around AgentGuard entirely | MCP client configured to talk to the real server directly; command run outside `agentguard exec` | None — architectural, not a bug | Not a mandatory chokepoint; see above |

1. **Prompt injection** — malicious content manipulates the agent into
   attempting an unintended action. AgentGuard does not detect the injection
   itself (it cannot see the agent's reasoning) — but MCP response
   inspection now flags an *injection-shaped response* as a detection
   signal, and the gateway blocks the *resulting* tool call the same as any
   other policy violation regardless.
2. **Malicious/untrusted MCP server** — `mcp.allowed_servers` plus
   `agentguard scan`'s MCP discovery flag any server not explicitly trusted;
   response inspection adds visibility into what an untrusted server
   actually returns.
3. **Credential exposure** — `filesystem.deny`/`warn` block/flag credential
   paths at runtime, in both the MCP gateway and `agentguard exec`;
   `agentguard scan` flags their mere presence as a standing exposure.
   Filesystem matching now lexically collapses `.`/`..` traversal segments
   before comparing — a value like `~/other/../.ssh/id_rsa` used to evade
   `filesystem.deny` entirely; see
   [SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md) F4. This is still not
   full canonicalization (no symlink resolution).
4. **Excessive filesystem access** — `filesystem.allow` scopes an agent to a
   workspace; anything outside it WARNs, in both adapters.
5. **Dangerous shell execution** — `shell.allowed`/`shell.deny`, enforced
   for MCP shell-style tool calls and, now, for any command actually routed
   through `agentguard exec` — with real prevention (never spawned) in the
   latter case. `shell.allowed`/`deny` now normalize basename and common
   Windows extensions before comparing (a bare `rm` entry used to miss
   `/bin/rm`/`rm.exe`/`RM.EXE`), and a general-purpose interpreter (node/
   python/sh/powershell/...) invoked with its inline-eval flag is BLOCKed
   by default even if the interpreter itself is allowed — see
   [SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md) F2/F3. The interpreter
   mitigation is narrow and stated as such: it does not stop a payload
   written to a file first and then run.
6. **Sensitive data exposure via a chained action** — a single sensitive
   read isn't inherently a violation; the correlation engine flags a
   sensitive read followed by external network activity in the same session
   as a pattern worth reviewing.
7. **Untrusted tools** — `agentguard scan`'s MCP discovery plus the
   untrusted-server-then-sensitive-access correlation rule.
8. **Agent misconfiguration** — `agentguard scan` surfaces a service bound
   to `0.0.0.0`, or a workspace with `.env`/credentials sitting where a
   misconfigured agent could reach them.

**Out of scope / explicitly not defended against:** a malicious or
compromised *MCP server binary itself* tampering with the gateway process; a
command or MCP call that bypasses AgentGuard's entry points entirely
(enforced by *configuration*, not a kernel-level guarantee); symlink/TOCTOU
attacks on filesystem paths; anything happening inside a real MCP
server/subprocess's own internals; true model intent (we observe actions and
their sequence, never reasoning).

## Security claims matrix

| Protects against | | Does not protect against |
|---|---|---|
| Prohibited MCP tool calls (routed through the gateway) | ✓ | Agents bypassing the gateway entirely | ✗ |
| Prohibited commands routed through `agentguard exec` | ✓ | Commands executed outside `agentguard exec` | ✗ |
| Known sensitive-resource patterns (paths, secret shapes) | ✓ | Host-wide filesystem/process activity | ✗ |
| Selected dangerous shell operations, incl. the interpreter-eval bypass | ✓ *(narrowed, see F2)* | Arbitrary OS-level process activity | ✗ |
| Selected suspicious MCP responses (secrets, injection-shaped text) | ✓ *(pattern-based, see F5)* | Unknown/semantic prompt injection | ✗ |
| Known correlated action sequences, within one session | ✓ | Cross-session / cross-adapter behavioral correlation | ✗ |
| Local AI/MCP posture discovery | ✓ | Tampered audit logs (observability, not forensic-grade) | ✗ |

Full detail, worked examples, and the reasoning behind each row:
[SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md#security-claims-matrix).

## Current capabilities

**Runtime — MCP gateway:** everything from Phase 1/2 (wraps a stdio MCP
server; heuristic request classification into filesystem/shell/network/secret
resources with `ActionType` tagging; ALLOW/WARN/BLOCK with risk and matched
rule; BLOCK never forwards), **plus (Phase 3):** response inspection on every
forwarded call's result; `agentId` captured from `clientInfo`; richer
`SecurityEvent`s (`direction`, `destination`, `metadata`).

**Runtime — `agentguard exec` (new):** evaluates a real, already-split
command+argv against the same policy before ever spawning it; BLOCK means
the process never runs; every run logged as a `SecurityEvent` with
`source: "shell-exec"`.

**Posture scanner (`agentguard scan`, unchanged from Phase 2):** detects
known local AI/agent runtimes, discovers MCP client configs (parses JSON
only, never executes), checks this machine's own listening-socket table for
exposure beyond localhost, checks sensitive-path existence/permissions only
(never contents), produces a `SecurityPosture`.

**Onboarding (`agentguard wrap` / `unwrap` / `status`, Phase 5):** finds the
MCP servers configured in known AI apps (one shared client list used by both
the scanner and `wrap`), and rewrites each stdio server's entry to launch
through the gateway. Preview by default; `--apply` backs up each file's exact
bytes first and writes atomically, refusing if the app changed the file in the
meantime. Every other key in an entry (`env`, `cwd`, ...) is preserved, and
the original command is recoverable from the wrapped entry itself, so
`unwrap` never depends on a separate state file. Generates
`~/.agentguard/policy.yaml` (the shipped defaults plus the servers you
approved) and one shared audit log. `status` reports every client and server
as protected, needs-repair, or not protected **and why**.

**`agentguard events` (Phase 3 additions):** `--risk <level>` and
`--blocked` filters on the displayed event list; runs the **correlation
engine** against each session's full (unfiltered) event set and prints any
resulting `Detection`s beneath that session.

## Limitations (read before you trust this for anything real)

**Runtime — both MCP gateway and `agentguard exec`:**
- **Enforcement boundary, not an EDR.** Only commands/calls actually routed
  through one of these two entry points are observed or enforced — anything
  bypassing them is invisible. This is the single most important limitation
  in the whole project.
- **Heuristic resource extraction, not schema-aware** (MCP side) — see the
  original Phase 1/2 caveats: name/shape-based guessing, occasional
  low-signal extra matches, no path canonicalization/symlink resolution.
- **Secret detection is a narrow pattern match**, not general DLP.
- **Network enforcement is best-effort, MCP-argument-visible destinations
  only** — full URLs, bare hostnames under `host`/`hostname`/`domain`-style
  keys, and the `Host:` header of raw HTTP request text. A destination under
  any other field name is not seen (F10 in `SECURITY-ASSESSMENT.md`), and
  there is no raw socket visibility into what a real MCP server process does
  on its own. An unlisted domain is a WARN, not a BLOCK.
- **`agentguard wrap` covers only what it knows and can safely edit.** It
  only looks in the known config locations (`src/adapters/discovery/client-configs.js`);
  an app not on that list is invisible to it (use `--config <file>` for a JSON
  file with an `mcpServers` section). Claude Code's own user settings file
  (`~/.claude.json`) is *discovered but never rewritten* — the app edits it
  continuously. **Remote (HTTP/SSE) MCP servers are not protected** — only
  stdio servers can be wrapped — and `status` says so per server. The app must
  be restarted for a change to take effect, an app update can rewrite its own
  config and drop the wrap (`status` shows it), and a server added later is
  unprotected until `wrap --apply` runs again. The gateway remains an
  opt-in boundary, not a mandatory chokepoint (see Threat model).
- **A BLOCK stops the tool call, not the model's knowledge.** In a real test, an
  AI app that had a (fake) key blocked from going to a tool then base64-encoded
  it itself in its chat reply, and described AgentGuard's error as a "connector
  hiccup" instead of relaying it. The gateway controls what reaches tools; it
  cannot control what a model says or how an app presents a tool error.
- **The generated policy is the permissive shipped default** plus an approved-
  server list: no network allowlist, so an unlisted domain never even WARNs
  until you add `network.allowed_domains`. Secrets in arguments are still
  BLOCKed, and sensitive paths still denied. A WARN is recorded in the audit
  log but **not shown in the AI app's chat** (only a BLOCK is, via its error).
- **On Windows, `.cmd` launchers (e.g. `npx`) are started through `cmd.exe`**;
  an argument containing `& | < > ^ % "` is refused with a message rather than
  escaped, and a `.cmd` path containing a space is refused.
- **MCP response inspection is pattern-matching, not comprehension** — will
  have both false positives (a legitimate response happens to contain
  "ignore" and "instructions" near each other) and false negatives (a
  rephrased injection attempt). It inspects `result` content only, not every
  possible MCP response shape.
- **`agentId` is only as trustworthy as what a client chooses to send** in
  `clientInfo.name` — nothing authenticates it. `agentguard exec` has no
  handshake at all, so it always falls back to its own `sessionId`.
- **Correlation is session-scoped and doesn't span adapters.** A gateway
  session and a separate `agentguard exec` run get different `sessionId`s
  today (visible directly in `npm run demo`'s output) — a pattern split
  across both is not detected. This is the direct consequence of the
  identity limitation above, not a separate bug.
- **Correlation rules are simple deterministic sequence checks**, not
  statistical/ML detection — they will miss variants and can, in principle,
  false-positive on an unusual-but-legitimate sequence. A `Detection` is a
  prompt for human review, not a verdict.
- **An allowed general-purpose interpreter (node/python/sh/powershell/...)
  is close to unrestricted code execution.** `shell.block_interpreter_eval`
  (default on) catches only the single most blatant case — a known
  interpreter plus its inline-eval flag. It does not catch a payload
  written to a file first and then run, or any interpreter/flag outside its
  small table. See [SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md) F2 —
  this is stated as a narrowing, not a fix.
- **MCP response inspection's cross-fragment check is narrow.** It only
  reconstructs strings collected under the conventional `text` key, joined
  with no separator — a deliberately inserted separator between fragments,
  or a response shape that doesn't use `text`, still evades it (F5).
- **No recursion-depth limit on nested MCP arguments/responses** — a
  sufficiently deep (but not circular; JSON itself can't be circular)
  structure will stack-overflow the request/response walkers. A real,
  bounded DoS surface, not fixed in this phase.
- **Filesystem path matching collapses `.`/`..` lexically, but is still not
  full canonicalization** — no symlink resolution, no filesystem access
  during matching (F4 closed the traversal-bypass direction, not the
  broader canonicalization gap).

**Posture scanner:** unchanged from Phase 2 — a small hand-maintained agent
registry (misses anything not in it), a fixed non-exhaustive list of MCP
config locations, network-exposure checking dependent on `netstat`/`lsof`
being available (degrades to nothing found, not a crash, if not), an
indicative (not calibrated) score, not a replacement for EDR, never
overclaims intent or malice.

## How to run the POC

Requires Node.js 20+.

```bash
npm install
npm test        # 192 tests: policy/risk engine, translation, discovery, correlation,
                 # response inspection, exec wrapper, wrap/unwrap/status (all with fake
                 # data sources or a sandboxed fake home where possible) + real
                 # end-to-end proxy/exec/CLI process spawns, plus 49 security-validation
                 # regression tests (test/security-validation/) — see SECURITY-ASSESSMENT.md
npm run demo    # the full narrative — see "DevDay demo flow" below
npm run scan    # agentguard scan against THIS machine
```

To protect the MCP servers **already configured** in the AI apps on a machine
(Claude Desktop, Google Antigravity, a project's `.mcp.json`) without
hand-editing JSON — see [docs/TESTER-GUIDE.md](docs/TESTER-GUIDE.md):

```bash
node bin/agentguard.js --help          # every command; `<command> --help` explains one
node bin/agentguard.js wrap            # PREVIEW: what would change; changes nothing
node bin/agentguard.js wrap --apply    # back up each config, then wrap its servers
node bin/agentguard.js status          # what is protected, what is not, and why
node bin/agentguard.js unwrap --apply  # restore every original entry
node bin/agentguard.js events          # shared audit log, no flags needed
```

To wrap a single real MCP server by hand:

```bash
node bin/agentguard.js gateway \
  --policy policy/default-policy.yaml --log audit.jsonl --server-name filesystem \
  -- npx -y @modelcontextprotocol/server-filesystem /path/to/workspace
```

To run a command through the same policy, with real prevention on BLOCK:

```bash
node bin/agentguard.js exec --policy policy/default-policy.yaml --log audit.jsonl -- git status
```

To review what happened afterward, with correlation:

```bash
node bin/agentguard.js events --log audit.jsonl [--session <id>] [--risk <level>] [--blocked]
```

The standalone `bin/agentguard-gateway.js` still works identically for the
gateway — `agentguard gateway` and `agentguard-gateway` call the exact same
underlying command.

## Configuring policies

(See [`policy/default-policy.yaml`](policy/default-policy.yaml) for the full
annotated reference, and `applyDefaults()` in
[`src/core/policy-engine.js`](src/core/policy-engine.js) for exact defaults.)

```yaml
filesystem:
  allow: []      # optional; if non-empty, anything outside it -> WARN
  deny: []       # -> BLOCK
  warn: []       # -> WARN

shell:
  allowed: []    # binaries allowed via an MCP shell-style tool call, or `agentguard exec`
                 # — normalized to basename with common Windows extensions stripped
  deny: []       # checked FIRST, always wins even over `allowed`
  block_interpreter_eval: true  # BLOCKs a known interpreter (node/python/sh/powershell/...)
                 # invoked with its inline-eval flag, even if the interpreter is itself
                 # allowed — narrow mitigation, see SECURITY-ASSESSMENT.md F2

mcp:
  allowed_servers: []   # empty = trust all; also used by `agentguard scan` for trust labels

network:
  allowed_domains: []   # empty = no restriction (best-effort visibility only)

secrets:
  block_exfiltration: true

mcp_response_inspection:
  block_on_secret_pattern: true          # mirrors the request-side default
  block_on_suspicious_instruction: false # log/WARN only by default
```

**Documented default-policy decisions** (deliberate, not arbitrary):

| Action | Verdict | Risk | Why |
|---|---|---|---|
| Read `~/.ssh/**`, `~/.aws/**`, etc. | **BLOCK** | CRITICAL | No legitimate agent workflow needs raw credential material. |
| Read `.env`, `.env.*` (in any directory) | **WARN** | HIGH | Often legitimate; a hard block breaks normal dev workflows, so it's surfaced with real weight instead. |
| Invoke a server not in `mcp.allowed_servers` | **WARN** (or ALLOW if empty) | MEDIUM | No server-reputation data; empty = trust everything configured. |
| Shell command not in `shell.allowed` (MCP or `agentguard exec`) | **BLOCK** | HIGH | Arbitrary shell execution is the highest-leverage action available; deny-by-default. |
| Shell command in `shell.deny` | **BLOCK**, always | HIGH | Wins even over `shell.allowed` — defense in depth. |
| A known interpreter (node/python/sh/...) invoked with its inline-eval flag | **BLOCK** | CRITICAL | `shell.allowed` only inspects the binary name; an allowed interpreter otherwise grants arbitrary code execution. Narrow mitigation, not a general fix — see SECURITY-ASSESSMENT.md F2. |
| A tool-call argument or response matching a known secret pattern | **BLOCK** | CRITICAL | Credential material should never cross this boundary in either direction. |
| A response matching an instruction-injection pattern | **WARN** by default | MEDIUM | A detection signal, not proof — blocking on keyword-matching alone is opt-in. |

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

A response-side event, and a correlation `Detection` printed by `agentguard events`:

```
[WARN] MCP request received
[WARN] Tool: search
[WARN] Policy decision: WARN
[WARN] Reason: Response contains an instruction-injection-shaped pattern. This is a detection signal, not confirmed compromise.
```

```
Detection: Potential sensitive-data exposure pattern
Severity: HIGH
Session: 56589f71-91e4-40cd-b5aa-795134c0276e
Agent: 56589f71-91e4-40cd-b5aa-795134c0276e
A sensitive file read (filesystem:.env) was followed by a network request (attacker.example.com) in the same session.
Recommendation: Review whether this agent session needed both sensitive-file access and external network access.
```

## Project layout

```
bin/agentguard.js             umbrella CLI: gateway | scan | events | exec
bin/agentguard-gateway.js     standalone gateway CLI (unchanged behavior, thin wrapper)

src/core/                     transport-agnostic: Action, ActionType, Decision, PolicyEngine,
                                 RiskEngine, SecurityEvent, SecurityFinding, SecurityPosture,
                                 Detection, CorrelationEngine, findings-rules, resource-heuristics,
                                 AuditLogger, glob matching

src/adapters/mcp/             MCP-specific: JSON-RPC translation, the stdio proxy, response inspection
src/adapters/shell/           the agentguard exec wrapper (real argv -> Action[], spawn only on non-BLOCK)
src/adapters/host/            OS primitives: process list, listening ports, PATH lookup
src/adapters/discovery/       agent detection, MCP config discovery, network exposure,
                                 sensitive-resource scan, and the scan orchestrator

src/cli/                      gateway-command, scan-command, events-command, exec-command

policy/default-policy.yaml    shipped reference policy
examples/                     the DevDay demo — the 7-Act narrative (docs/DEV-DAY-DEMO.md) + its policy
test/                         unit tests (dependency-injected, no reliance on host state) +
                                 real end-to-end proxy/exec/CLI process spawns + a live scan
test/security-validation/     red-team reproduction tests, one per finding in
                                 SECURITY-ASSESSMENT.md — asserts the FIXED behavior;
                                 a regression here means a bypass came back

SECURITY-ASSESSMENT.md        adversarial self-assessment: findings, fixes,
                                 residual risk, security claims matrix
docs/architecture.md          the architecture diagram, enforcement boundaries vs. trust boundary
docs/DEV-DAY-DEMO.md          timed presenter script for npm run demo
docs/DEV-DAY-QA.md            prepared answers to likely judge questions
```

## DevDay demo flow

`npm run demo` runs a 7-Act narrative for real, against real code — nothing
simulated, no real secrets, no real destructive commands (the MCP server is
a fixture that never touches the real filesystem/network; the `curl` exfil
attempt in Act 6 is BLOCKed before AgentGuard ever calls `spawn()` on it).
See [docs/DEV-DAY-DEMO.md](docs/DEV-DAY-DEMO.md) for the full narrated
timing script; in short:

1. **The Problem** — printed framing, no code runs yet.
2. **Discover** (`agentguard scan`) — posture snapshot of the actual
   machine running the demo.
3. **Normal agent activity** — a plain file read → ALLOW, LOW risk.
4. **Suspicious response** — the fixture server's reply contains an
   instruction-injection-*shaped* phrase → response inspection WARNs.
5. **Sensitive resource** — `.env` → WARN, then `~/.ssh/id_rsa` → **BLOCK**
   (the real MCP server never receives that request).
6. **Dangerous execution** (`agentguard exec`) — a raw `curl` exfiltration
   attempt, BLOCKed *before* `spawn()` is ever called.
7. **Correlation** (`agentguard events`) — the full session timeline, plus
   the correlation engine firing "Potential sensitive-data exposure
   pattern" (HIGH). Act 6's BLOCK appears as its own, separate session — a
   live, honest illustration of the doesn't-span-adapters correlation
   limitation, printed explicitly at the end rather than hidden.

## Future Work

Not built, and intentionally not attempted here:

- **HTTP/SSE MCP transport** — deferred by explicit agreement: real
  Streamable-HTTP/SSE support is separate transport plumbing (likely via the
  official `@modelcontextprotocol/sdk`, to avoid hand-rolling a networking
  stack) and shouldn't distract from the runtime-security story.
- **Filesystem/network adapters** producing real (non-MCP, non-exec)
  `Action`s — e.g. an fs-watcher — feeding the same `PolicyEngine`.
- **Real OS-level network enforcement** via a proxy, rather than
  best-effort URL-argument/response inspection.
- **Cross-adapter session identity** so a gateway session and an
  `agentguard exec` run by the same agent correlate as one — needs a real
  identity mechanism beyond MCP's `clientInfo`.
- **Richer correlation**: more rules, cross-session correlation, and
  eventually — explicitly not yet — anomaly detection or LLM-assisted risk
  evaluation, still deliberately deferred so this stays deterministic and
  explainable.
- A dashboard, automated remediation, secret rotation — all still out of
  scope per the project's own non-goals.
