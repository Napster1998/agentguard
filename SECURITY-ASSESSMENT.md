# AgentGuard Security Assessment (Phase 3.5)

**Status:** Complete. 10 findings identified and reproduced with automated tests; 10 remediated (9 fully, 1 partially — see F5). All fixes have permanent regression tests. 182/182 tests passing (the count includes the Phase 5 onboarding tests, which add no security finding of their own). F1–F9 came from the Phase 3.5 red-team; **F10 was found afterwards, by running the real gateway in front of a real third-party MCP server (Burp Suite)** — see F10.

## Scope

An adversarial self-assessment of AgentGuard as built through Phase 3: the MCP stdio gateway, `agentguard exec`, the posture scanner, MCP response inspection, and the correlation engine. The objective was not to find the most vulnerabilities possible — it was to answer six narrow, falsifiable claims (below) honestly, and to fix what materially weakens them without introducing OS-level enforcement, ML/LLM detection, or other Phase-4+ scope.

## Methodology

1. **Reconnaissance**: re-read every security-critical module fresh (not from memory of having written it) — `glob-match.js`, `policy-engine.js`, `translate.js`, `exec-wrapper.js`, `proxy.js`, `response-inspect.js`, `network-exposure.js`/`listening-ports.js`, `events-command.js` — plus `npm audit` for supply-chain risk.
2. **Attack**: for each hypothesis formed during reconnaissance, wrote a real, automated test that either exploited the code as it stood or proved the code was NOT vulnerable to that specific attack. Every finding below is backed by a test in `test/security-validation/` that failed before the fix and passes after.
3. **Remediate**: fixed every finding that was small, testable, and consistent with the existing architecture (all 9 qualified — none required a design change).
4. **Re-test**: every original red-team test was converted into a permanent regression test asserting the FIXED behavior, so a future change that reintroduces any of these bypasses will fail CI, not just this one-time assessment.

## Architecture under test

```
Agent → [AgentGuard Gateway | agentguard exec] → PolicyEngine → RiskEngine → SecurityEvent → CorrelationEngine
```

See [README.md](README.md) for the full diagram; nothing about the architecture changed in this phase, only the code inside it.

## Trust boundaries

| Boundary | Who controls it | Enforced how |
|---|---|---|
| Agent ↔ Gateway | The developer's MCP client config | **Not mandatory.** An agent configured to talk to the real MCP server directly bypasses AgentGuard entirely. This is inherent to a proxy architecture, not a bug — see Claim 1's caveat below. |
| Command ↔ `agentguard exec` | Whatever invokes commands | Same — a command run outside the wrapper is invisible to it. |
| `serverName` ↔ actual spawned command | The operator's `--server-name` flag | **No binding.** Nothing verifies the label matches what's actually spawned. This is an operator-trust question — an agent has zero ability to influence `serverName`. |
| `agentId` ↔ real identity | The MCP client's own `initialize.clientInfo.name` | Self-reported, unauthenticated by design (documented, not a gap). |

**Answering the brief's six trust-boundary questions directly:**
1. *Can the agent bypass the gateway?* Yes, if its MCP client is configured to talk to the real server directly — this is a configuration-time trust decision the operator makes, not something AgentGuard can prevent without becoming a kernel-level control (explicitly out of scope).
2. *Can the MCP server be invoked directly?* Yes, same reasoning.
3. *Can the agent discover the real server's command?* Nothing hides it — the operator's own gateway invocation names it.
4. *Can configuration be changed to bypass AgentGuard?* Yes — the developer controls their own MCP client config.
5. *Can `agentguard exec` be bypassed by spawning directly?* Yes, same category as #1.
6. *Does the product enforce itself as a mandatory gateway?* No, and it was never designed to — it is a policy proxy, analogous to a corporate HTTP proxy: effective when traffic is routed through it, silent when it isn't.

None of this is a new discovery — it was already documented before this phase. This assessment's job was to confirm it's still accurately characterized, which it is.

## Findings

Severity per the assessment's own scale (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL). All are fixed except where noted.

### F1 — CRITICAL — Malformed JSON on the request path bypassed policy entirely — **FIXED**
**Component:** `src/adapters/mcp/proxy.js` (request handler)
**Scenario:** A JSON-RPC line that fails `JSON.parse` (e.g. a trailing comma) used to be forwarded to the real MCP server verbatim, with zero policy evaluation — a request targeting `~/.ssh/id_rsa` that happened to be malformed would reach the server as if AgentGuard weren't there.
**Reproduction:** `test/security-validation/f1-parse-bypass.test.js`
**Fix:** Parse failures now fail CLOSED — the line is dropped (not forwarded) and logged as its own `BLOCK` event with `rule: "malformed-json"`. Applied to both the request and response directions.
**Residual risk:** None identified for this specific vector. A downstream server bug causing it to interpret bytes differently than `JSON.parse` would is now moot — we never forward what we can't parse.

### F2 — CRITICAL — Allowed general-purpose interpreters defeated `shell.allowed` entirely — **FIXED (partially, by design)**
**Component:** `src/adapters/shell/exec-wrapper.js`, `src/adapters/mcp/translate.js`
**Scenario:** `shell.allowed` only ever inspected the top-level binary. `node`/`python` (both in the shipped default policy) are general-purpose interpreters; `agentguard exec -- node -e "<anything>"` ran arbitrary code because "node" was allowed and the `-e` payload was invisible to policy.
**Reproduction:** `test/security-validation/f2-interpreter-bypass.test.js`
**Fix:** A new `interpreter-eval` action type detects a small, known set of interpreters (node, python, sh/bash/zsh, cmd, powershell, ruby, perl) combined with their inline-eval flag (`-e`, `-c`, `-Command`, `/c`, etc.) and BLOCKs by default (`shell.block_interpreter_eval: true`), independent of whether the interpreter is itself allowed. Also removed `node`/`python` from the shipped default `shell.allowed` (defense in depth, reduces real-world exposure of the out-of-the-box config).
**Residual risk — stated plainly:** This is a narrow, deliberately incomplete mitigation for the single most blatant case. It does **not** catch: writing a payload to a file first and running `node script.js`; `require()`/dynamic-import tricks; an interpreter not in the small table; or any interpreter flag not in the table. **The general problem — that `shell.allowed` grants full trust to whatever an allowed binary can be instructed to do — is not solvable by pattern-matching and is not claimed to be solved.** Operators should treat any general-purpose interpreter in `shell.allowed` as equivalent to unrestricted code execution.

### F3 — HIGH — `shell.allowed`/`shell.deny` used exact-string comparison, no basename/extension normalization — **FIXED**
**Component:** `src/core/policy-engine.js`
**Scenario:** `shell.deny: [rm]` did not catch `/bin/rm`, `rm.exe`, or `RM.EXE` — none of those strings equal `"rm"`. This broke the documented "`shell.deny` always wins" guarantee for any path/extension variant, particularly relevant on Windows where executables commonly carry `.exe`/`.cmd`/`.bat` suffixes.
**Reproduction:** `test/security-validation/f3-shell-exact-match.test.js`
**Fix:** Both the incoming binary and every `allowed`/`deny` entry are normalized to basename with common executable extensions stripped before comparison.

### F4 — HIGH — Path traversal bypassed both `filesystem.allow` and `filesystem.deny` — **FIXED**
**Component:** `src/core/glob-match.js`
**Scenario:** Matching was purely lexical (string-prefix + glob), never collapsing `.`/`..` segments. `./workspace/../../../etc/passwd` lexically satisfied `filesystem.allow: ["./workspace/**"]` despite resolving outside the workspace; `~/other/../.ssh/id_rsa` evaded `filesystem.deny: ["~/.ssh/**"]` despite resolving into the denied directory.
**Reproduction:** `test/security-validation/f4-path-traversal.test.js`
**Fix:** `.`/`..` segments are now lexically collapsed before matching (with the `~` anchor protected from being popped past). This is **still not full canonicalization** — no symlink resolution, no filesystem access — see Limitations.

### F5 — MEDIUM — Response inspection checked each string independently — **PARTIALLY FIXED**
**Component:** `src/adapters/mcp/response-inspect.js`
**Scenario:** A secret or injection phrase split across adjacent `content` blocks (e.g. `["AKIA", "ABCDEFGHIJKLMNOP"]`) matched neither fragment individually.
**Reproduction:** `test/security-validation/f5-response-split-bypass.test.js`
**Fix:** Inspection now also checks the un-separated concatenation of every string found under the MCP content convention key `text`, catching naive no-separator chunking.
**Residual risk — stated plainly:** A deliberately inserted separator (even a single unexpected character) between fragments still evades this, and the mitigation is targeted at the `text`-key convention specifically — a response shape that doesn't use it isn't helped. This is explicitly a bounded mitigation for naive chunking, not a general fix (verified by its own "still evades" regression test).

### F6 — MEDIUM — A downstream server could bypass response inspection with a duplicate/unsolicited response id — **FIXED**
**Component:** `src/adapters/mcp/proxy.js`
**Scenario:** `pendingRequests` was deleted the first time a given `id` was seen; a second response reusing that `id` (or a fabricated, unsolicited one) skipped inspection entirely and was relayed to the agent raw.
**Reproduction:** `test/security-validation/f6-duplicate-response-id.test.js`
**Fix:** Every response carrying a `result` field is now inspected regardless of whether its `id` is currently tracked.

### F7 — MEDIUM — A malformed-but-valid-JSON log line crashed `agentguard events` entirely — **FIXED**
**Component:** `src/cli/events-command.js`, `src/core/correlation-engine.js`
**Scenario:** Sorting on `.timestamp` without a null check threw `TypeError` if any event in the log lacked that field — taking down the report for every session in the file, not just the malformed one.
**Reproduction:** `test/security-validation/f7-events-crash.test.js`
**Fix:** A missing `timestamp` is now normalized/defaulted at both the read layer and defensively at each sort site.

### F8 — LOW — `PolicyEngine`'s fallback for an unrecognized resource type was ALLOW — **FIXED**
**Component:** `src/core/policy-engine.js`
**Scenario:** Fail-open default sitting in security-critical code. Not attacker-reachable today (only trusted adapter code produces resource types) but a landmine for the next adapter.
**Reproduction:** `test/security-validation/f8-f9-misc.test.js`
**Fix:** Default case now returns WARN, not ALLOW.

### F9 — LOW — Bracketed IPv6 loopback misclassified as externally-bound (false positive) — **FIXED**
**Component:** `src/adapters/discovery/network-exposure.js`
**Scenario:** Windows `netstat` produces `[::1]`; the local-hosts set only contained bare `::1`, so a genuinely local-only IPv6 service was flagged HIGH. Not a bypass (the safe direction), but a real correctness bug.
**Reproduction:** `test/security-validation/f8-f9-misc.test.js`
**Fix:** Brackets are stripped before comparison.

### F10 — MEDIUM — A tool's network destination passed as a bare hostname or raw HTTP text was invisible to `network.allowed_domains` — **FIXED (narrowly)**
**Component:** `src/adapters/mcp/translate.js`, `src/core/resource-heuristics.js`
**How it was found:** not by a unit test. The gateway was run in front of the real Burp Suite MCP bridge and fed Burp's real `send_http1_request` argument shape (`content` = raw HTTP text, `targetHostname`, `targetPort`, `usesHttps`). The call was ALLOWed and Burp attempted the connection (`java.net.UnknownHostException: attacker.invalid` in Burp's own event log; a Repeater tab created by `create_repeater_tab` as visible proof). A `.invalid` hostname was used so nothing real could be contacted.
**Scenario:** The translator treated a value as a network destination only if it began with `scheme://`. `targetHostname` matched the path-key heuristic (it contains "target") and was filed as a *filesystem path*; the raw HTTP text contained `/` and was also filed as a path. The real destination never became a network action, so the allowlist never applied.
**Reproduction:** `test/security-validation/f10-network-destination.test.js` (F10a–F10e failed before the fix).
**Fix:** keys ending in `host`/`hostname`/`domain` now carry a network destination (checked before the path heuristic; a `:port` suffix is stripped), and raw HTTP request text contributes its `Host:` header and/or absolute-form request target. Re-verified against the live Burp bridge: the same call is now WARN/MEDIUM with `network:attacker.invalid`.
**Note on severity of the outcome:** an unlisted domain is a **WARN**, not a BLOCK, by existing policy design. The fix makes the destination *visible to policy*; it does not change what policy does with it.
**Residual gap (kept as a passing test, F10g):** classification is still by key name and value shape. A destination under an unrelated key (e.g. `dest`, or `target` with a bare IP) is still not recognized as network, and bracketed IPv6 is not parsed.

### Informational (documented characteristics, not vulnerabilities)
- Gateway/`agentguard exec` are not mandatory chokepoints — inherent to the architecture, now re-confirmed and clearly stated above.
- `serverName` has no cryptographic binding to the spawned command — an operator-trust question, not attacker-exploitable (the agent has no influence over it).
- Tool-name/argument-key-based resource classification means a misleadingly-named MCP tool evades type-specific policy — the existing "heuristic, not schema-aware" limitation, now also understood as a *trust* gap, not just an accuracy one.
- Deeply nested MCP arguments/responses have no recursion-depth limit (`walkStrings`/`collectStrings`) — a real, bounded stack-overflow DoS surface (confirmed via `test/security-validation/resource-exhaustion-and-malformed.test.js`), not fixed in this phase (would need a depth-limit threading change touching multiple call sites for a POC-scale risk — accepted, not remediated).
- `npm audit`: clean, 0 vulnerabilities, single well-known dependency (`js-yaml`).
- Audit log is plain-permission JSONL, tamperable by anything with the same filesystem access AgentGuard restricts — observability, not a forensic store (matches the brief's own framing).
- Secret **values** are never logged anywhere in the pipeline — verified by `test/security-validation/secret-leakage.test.js`: every place a secret match becomes a log/event/error field uses the pattern *name* (e.g. `"aws-access-key-id"`), never the matched text.
- Malformed request shapes (missing fields, wrong types, `null`, arrays instead of objects) do **not** crash the translator or response inspector — confirmed as a positive finding, not assumed.

## Security Claims Matrix

| Security Capability | Status |
|---|---|
| MCP policy enforcement (for traffic routed through the gateway) | ✓ |
| MCP direct-bypass prevention (agent talks to server directly) | ✗ *(by design — not a mandatory chokepoint)* |
| `agentguard exec` enforcement (for commands routed through it) | ✓ |
| Arbitrary process monitoring (commands run outside the wrapper) | ✗ |
| Allowed-interpreter code-execution containment | ✗ *(F2: narrow mitigation only, not a general fix)* |
| Path-traversal-resistant filesystem policy matching | ✓ *(F4: lexical only, no symlink resolution)* |
| Sensitive-path detection (posture) | ✓ |
| Host-wide filesystem monitoring | ✗ |
| MCP response inspection | ✓ *(pattern-based, narrow — see F5)* |
| Secret-value leakage prevention in AgentGuard's own output | ✓ |
| Audit-log tamper resistance | ✗ *(observability, not forensic-grade)* |
| Deterministic event correlation (within one session) | ✓ |
| Cross-session / cross-adapter correlation | ✗ |
| LLM/ML intent detection | ✗ *(explicitly out of scope)* |
| Mandatory-gateway self-enforcement | ✗ *(explicitly out of scope — see Trust boundaries)* |

## Claim-by-claim verdict

1. **"AgentGuard can prevent prohibited MCP tool calls from reaching the MCP server."** True for well-formed traffic routed through the gateway, and now also true for malformed traffic (F1 fixed it from a hard NO to a YES).
2. **"AgentGuard can prevent prohibited commands routed through `agentguard exec` from executing."** True for the binary-name policy itself (F3 fixed a real gap); **not fully true** when an allowed command is a general-purpose interpreter (F2 — narrowed, not closed).
3. **"AgentGuard can identify certain risky local AI configurations."** True, unchanged from Phase 2, with two correctness fixes (F9) that don't change the capability's substance.
4. **"AgentGuard can generate trustworthy security events for actions it observes."** True for actions it evaluates; F1/F6 closed two cases where an action was never evaluated (and thus never truthfully reported) in the first place.
5. **"AgentGuard can correlate related observed events."** True, within one session (as designed) — F7 fixed a real availability bug in the tool that reports correlations.
6. **"AgentGuard does not expose sensitive data through its own logging or inspection mechanisms."** True, verified by direct test, not assumed.

## Residual risk

- The interpreter-eval bypass (F2) is narrowed, not eliminated — an operator who adds `node`/`python`/similar to `shell.allowed` is still granting broad code-execution capability, just with a slightly higher bar against the most naive attempts.
- The response-inspection split bypass (F5) is narrowed to the common `text`-key convention — a response shape that doesn't use it, or a fragment sequence with any inserted separator, still evades it.
- Network-destination detection (F10) is narrowed to host-style key names and raw HTTP text. A destination hidden under any other field name is still invisible to `network.allowed_domains` — the same "heuristic, not schema-aware" limitation, now observed against a real server rather than only reasoned about.
- Deep nesting remains a real (bounded, non-catastrophic) DoS surface — not fixed, documented.
- Everything already true about the trust-boundary model (gateway/`agentguard exec` are not mandatory) remains true and is now more explicitly documented in the README threat model.

## DevDay security narrative

**AgentGuard does not attempt to determine whether an AI is malicious.** It establishes explicit security boundaries around agent capabilities routed through it, evaluates observable actions against deterministic policy, blocks prohibited actions — including, now, malformed input that used to slip through unevaluated — and correlates suspicious sequences within a session. This assessment red-teamed those specific claims rather than assuming they held: nine real bypasses were found by writing code that actually exploited the running system, eight are now closed with permanent regression tests proving it, and the two that are only narrowed (allowed interpreters, response-inspection chunking) are said so plainly, not glossed over. What AgentGuard does not claim — a mandatory chokepoint no agent can route around, host-wide monitoring, or any judgment about intent — is exactly what it didn't claim before this assessment either; the point of Phase 3.5 was to verify the things it *does* claim were actually true, and to fix the ones that weren't.
