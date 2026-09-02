# DevDay Demo Script

## Before the demo

**Environment:**
- Node.js 20+ on the presenting machine.
- A terminal window sized generously (this gets projected — bigger font,
  fewer wrapped lines).
- Colors help but aren't required: every ALLOW/WARN/BLOCK line carries the
  plain text label regardless of whether the projector renders ANSI color
  correctly. If unsure, test once beforehand (`node examples/run-demo.mjs`
  in the actual presentation terminal) rather than assuming.

**Commands to run once, before walking on stage:**
```bash
npm install
npm test
```
Confirms a clean baseline (133+ tests passing) and warms Node's module
cache so the live demo starts fast.

**Expected state:** nothing else needed. `npm run demo` is self-contained —
it spawns its own fixture MCP server, writes its own temp audit log, and
deletes it at the end. It does not read any of your real credentials,
`.env` files, or SSH keys, and does not need network access. Safe to run
more than once in a row if something needs a re-run.

## The script (~4 minutes, timings approximate)

Run: `npm run demo`

| Time | Act | What to say while it scrolls |
|---|---|---|
| 0:00 | **Problem** (printed) | "AI agents are increasingly running on developer machines — machines with source code, credentials, cloud config, internal tools. What happens when an agent does something it shouldn't?" |
| 0:20 | *(pause on architecture, optional)* | Pull up `docs/architecture.md` or just describe it: "Two enforcement boundaries — an MCP gateway, and a command wrapper — both feed one policy engine. That's the whole idea." |
| 0:50 | **Act 2 — Discover** (`agentguard scan`) | "Before any agent runs, we ask: what's already here?" Point at the posture output — AI runtime detected, an MCP server found, a sensitive path flagged. "This is what *could* happen — not a runtime decision yet." |
| 1:30 | **Act 3 — Normal activity** | A plain file read. "ALLOW, LOW risk. AgentGuard doesn't just block things — most of what an agent does is fine, and it stays fast and out of the way." |
| 1:50 | **Act 4 — Suspicious response** | The fixture MCP server's reply contains an instruction-injection-*shaped* phrase. "We're not claiming to detect prompt injection — we can't see the agent's reasoning. We flag the pattern as a signal: WARN." |
| 2:15 | **Act 5 — Sensitive resource** | `.env` → WARN. `~/.ssh/id_rsa` → **BLOCK**. "And this is the important part: the real MCP server never received this request. Not logged-then-ignored — never sent." |
| 2:45 | **Act 6 — Blocked execution** | `agentguard exec -- curl ...`. "Same idea, different entry point — a raw shell command. This is evaluated *before* the process is ever spawned. `spawn()` is never called. This proves AgentGuard isn't just watching after the fact." |
| 3:15 | **Act 7 — Correlation** | `agentguard events`. Walk the timeline top to bottom, then land on the `Detection:` block. "None of these steps alone is damning. The pattern — a sensitive read followed by outbound activity — is what gets flagged." |
| 3:45 | **Scope note** (printed automatically) | Point at the two different session ids. "This is deliberate honesty, not a bug we're hiding: correlation today is scoped to one session. MCP and exec have separate identities, so we don't claim to connect them yet." |
| 4:00 | **Closing** | "We don't try to decide whether the AI is good or evil. We define what it's allowed to do, observe what it actually does, and enforce that boundary at runtime." |

## If something goes wrong live

- **A step times out / hangs:** kill it (`Ctrl+C`) and re-run `npm run
  demo` from the top — it's idempotent, nothing persists between runs.
- **Colors look wrong on the projector:** ignore it and keep talking — the
  bracketed `[ALLOW]`/`[WARN]`/`[BLOCK]` text is the real signal, color is
  decoration.
- **A judge asks to see the code mid-demo:** `agentguard exec`'s check is
  in `src/adapters/shell/exec-wrapper.js` (the BLOCK-before-`spawn()`
  logic is about 10 lines), and the correlation rules are in
  `src/core/correlation-engine.js` — both are short enough to read on
  screen live if asked.
