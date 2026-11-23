# AgentGuard Architecture

One diagram, read top to bottom: an agent's actions flow down through two
enforcement boundaries into a shared policy/risk core, and every decision
becomes an event that a separate correlation pass can reason about later.

```
                              AI AGENT
                                 │
                   ┌─────────────┴─────────────┐
                   ▼                           ▼
          ┌──────────────────┐        ┌──────────────────┐
          │   MCP Gateway     │        │  agentguard exec  │
          │  (stdio proxy)    │        │ (command wrapper) │
          │                   │        │                   │
          │ tools/call         │        │ real argv          │
          │  --> Action[]       │        │  --> Action[]       │
          └─────────┬─────────┘        └─────────┬─────────┘
                    │  ENFORCEMENT BOUNDARY: only traffic  │
                    │  actually routed through one of      │
                    │  these two entry points is observed  │
                    │  or enforced. Nothing else is.        │
                    └───────────────┬───────────────────────┘
                                    ▼
                            ┌───────────────┐
                            │ Policy Engine  │
                            │ (sensitivity)  │
                            └───────┬───────┘
                                    ▼
                            ┌───────────────┐
                            │  Risk Engine   │
                            └───────┬───────┘
                                    ▼
                        ┌───────────────────────┐
                        │  ALLOW / WARN / BLOCK   │
                        │                        │
                        │  BLOCK => the MCP call  │
                        │  is never forwarded;    │
                        │  the exec command is    │
                        │  never spawn()ed.       │
                        └───────────┬───────────┘
                                    ▼
                          ┌───────────────────┐
                          │  SecurityEvent      │
                          │  (JSONL audit log)  │
                          └─────────┬─────────┘
                                    ▼
                          ┌───────────────────┐
                          │ Correlation Engine  │
                          │ (agentguard events)  │
                          └─────────┬─────────┘
                                    ▼
                          ┌───────────────────┐
                          │ Detection / Report  │
                          └───────────────────┘
```

**A third entry point (Phase 6, in progress): the Antigravity hook.**
`agentguard hook antigravity` (`src/adapters/antigravity/`) is run *by*
Google Antigravity before each tool call, as a `PreToolUse` hook. It turns the
call into the same `Action`s, evaluates them with the same Policy Engine and
answers `allow` or `deny`. A deny means the tool never runs.

It covers the agent's built-in tools (file read/write/edit) and its MCP calls.
An MCP call is translated with the gateway's own MCP translator, and servers
already behind the gateway are left to it. `run_command` is recorded but not
yet enforced. As with the other two entry
points, nothing it isn't asked about is seen: a tool call only reaches it if
Antigravity's hook configuration routes it there.

## Two labels that matter more than the boxes

**ENFORCEMENT BOUNDARY** (marked above): the MCP Gateway and `agentguard
exec` are where AgentGuard actually *does* something — evaluate, then
either forward/spawn or don't. Both feed the identical Policy Engine /
Risk Engine, which is the whole point of keeping `Action` transport-agnostic
(see `src/core/action.js`): a third adapter later would slot in the same
way, no changes to the engine.

**KNOWN TRUST BOUNDARY** (not drawn as a box, because it's an absence, not
a component): neither enforcement boundary is a mandatory chokepoint. An
agent's MCP client can be configured to talk to the real server directly;
a command can be run without going through `agentguard exec`. Both are
invisible to AgentGuard when that happens. This is inherent to a userspace
proxy — the same way a corporate HTTP proxy only sees traffic actually sent
to it — not a gap introduced by an implementation shortcut. See
[SECURITY-ASSESSMENT.md](../SECURITY-ASSESSMENT.md) for the full trust
boundary analysis, and the README's threat model for the asset-by-asset
breakdown.

## A second, parallel pipeline: posture

`agentguard scan` is architecturally independent of everything above — it
doesn't need the gateway running, and the gateway doesn't need a scan to
have been run. It answers a different question (*what could happen*, not
*what did happen*) and produces a different artifact (`SecurityPosture`:
findings, severity counts, an indicative score) rather than a stream of
events. See the README's "Posture vs. Runtime vs. Correlation" section —
the two are deliberately never merged into one number.

## Module map

| Concept | Where it lives |
|---|---|
| `Action`, `Decision`, `ActionType` | `src/core/action.js`, `src/core/decision.js` |
| `PolicyEngine` | `src/core/policy-engine.js` |
| `RiskEngine` | `src/core/risk-engine.js` |
| `SecurityEvent`, `AuditLogger` | `src/core/security-event.js`, `src/core/audit-logger.js` |
| `Detection`, `CorrelationEngine` | `src/core/detection.js`, `src/core/correlation-engine.js` |
| `SecurityFinding`, `SecurityPosture` | `src/core/security-finding.js`, `src/core/security-posture.js` |
| MCP adapter (translate, proxy, response inspection) | `src/adapters/mcp/` |
| Shell adapter (`agentguard exec`) | `src/adapters/shell/` |
| Antigravity hook adapter (`agentguard hook antigravity`) | `src/adapters/antigravity/` |
| Posture discovery (host primitives + orchestration) | `src/adapters/host/`, `src/adapters/discovery/` |
| CLI commands | `src/cli/`, entrypoints in `bin/` |
