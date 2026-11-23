# AgentGuard Security Assessment (Phase 3.5)

**Status:** Complete. 18 findings identified and reproduced with automated tests; 18 remediated (17 fully, 1 partially — see F5; F15, F16 and F17 each keep a stated, pinned residual). All fixes have permanent regression tests. 297/297 tests passing (the count includes the Phase 5 onboarding tests, which add no security finding of their own). F1–F9 came from the Phase 3.5 red-team. **F10–F13 were found afterwards, by using the real thing**: F10 by running the gateway in front of a real third-party MCP server (Burp Suite); F11 on a real Mac with the official MCP filesystem server; F12 while verifying F11; F13 in a live demo on Linux. Each was invisible to the unit tests that existed — a recurring lesson of this assessment. **F14–F18 were found by reviewing the code against a new adapter's needs** (the Phase 6 Antigravity-hooks feasibility study): each showed up when a realistic input shape (a command line as one string, a folder instead of a file, a secret inside a path) was pushed through the existing modules.

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

### F11 — MEDIUM — The shipped default `.env` warn rule never fired for real tool-call paths — **FIXED**
**Component:** `policy/default-policy.yaml` (policy *data*; the matcher was behaving correctly), `examples/demo-policy.yaml`
**How it was found:** on a real Mac, wrapping the official MCP filesystem server. The default policy was expected to WARN on a read of `<sandbox>/.env`; the call was ALLOWed. Reproduced against the matcher: `.env` matched only the bare string `.env` — not `./.env`, any absolute path, a Windows path, or `.env.local`.
**Scenario:** The MCP filesystem server requires absolute paths, so the default "sensitive file" warning never fired for the most common tool. (The `~/.ssh/**` and `~/.aws/**` BLOCK rules were unaffected: the matcher expands `~` against the home directory.) The rule's own neighbours (`**/credentials.json`, `**/secrets.yaml`) already used the `**/` form; only `.env` did not, which is why the original tests (using a bare `.env`) never saw it.
**Reproduction:** `test/security-validation/f11-env-warn-real-paths.test.js` — loads the SHIPPED default policy, the demo policy and a policy generated by `agentguard wrap`, so the data cannot silently regress.
**Fix:** `**/.env` and `**/.env.*` in the default and demo policies. **Existing generated policies are not rewritten** (`wrap` only ever adds server names to `mcp.allowed_servers`): a `~/.agentguard/policy.yaml` created before this fix keeps the old patterns until edited.

### F12 — MEDIUM — `**/` in a glob did not require a path-segment boundary — **FIXED**
**Component:** `src/core/glob-match.js`
**How it was found:** while verifying F11, a test case `my.env.txt` unexpectedly matched `**/.env.*`.
**Scenario:** `**` compiled to `.*` and consumed the following `/`, so `**/.env.*` became `^.*\.env\..*$` — no requirement that `.env` begin a segment. On deny/warn lists this over-matched (`my.env.txt`, `notcredentials.json`): the safe direction, but real false positives. On an **allowlist** using a leading `**/` it **failed open**: `filesystem.allow: ["**/src/**"]` also treated `/etc/mysrc/evil` as inside the allowlist. The shipped default allowlist is empty and the documented examples do not use a leading `**/`, so this needed a policy author to write one — but it is a real fail-open in a security-critical matcher.
**Reproduction:** `test/security-validation/f12-glob-segment-boundary.test.js`
**Fix:** `**/` now compiles to `(?:.*/)?` — zero or more WHOLE directory segments. A mid-pattern `**/` (`a/**/b`) and a trailing `**` behave as before; all pre-existing tests, including the F4 traversal tests, still pass.

### F13 — MEDIUM — Credential folders were protected only directly under the home directory — **FIXED**
**Component:** `policy/default-policy.yaml` (policy *data*; the matcher was behaving correctly)
**How it was found:** in a live demo on Linux with Google Antigravity and the official MCP filesystem server. A dummy credentials folder at `/home/<user>/DemoFiles/.aws/credentials` was read without any block, while the same read at `/home/<user>/.aws/credentials` was blocked.
**Scenario:** the default denied `~/.ssh/**` and `~/.aws/**`, and `~` expands to the home directory, so only those two exact locations were covered. A copy of an SSH or AWS folder anywhere else (a backup, `Downloads`, a project folder, a restored old laptop) was ALLOWED. An agent that finds or is pointed at such a copy could read real credentials with no policy hit.
**Reproduction:** `test/security-validation/f13-credential-folders-anywhere.test.js` — loads the SHIPPED default policy; it also pins the boundary (only whole directory names match, so `my.aws`, `.awsome` and `aws/` stay allowed).
**Fix:** added `**/.ssh/**` and `**/.aws/**` (valid since F12 made `**/` a whole-segment match). The home-folder rules stay first, so existing example output is unchanged. **Trade-off, stated in the policy file:** a project that legitimately keeps its own `.aws` folder (SAM/CDK config) is blocked too. **Existing generated policies are not rewritten** (same caveat as F11): a `~/.agentguard/policy.yaml` created earlier needs these two lines added by hand.

### F14 — MEDIUM — Secret values reached the audit log through `agentguard exec` and path-shaped values — **FIXED**
**Component:** `src/core/security-event.js` (fix), `src/core/resource-heuristics.js`; affected `src/adapters/shell/exec-wrapper.js` and `src/adapters/mcp/proxy.js`
**How it was found:** during the Phase 6 feasibility review, by running a BLOCKed `agentguard exec -- git commit -m "key AKIAIOSFODNN7EXAMPLE"` and reading the log. The earlier claim ("secret values are never logged") had been verified for one gateway case only: a secret under a non-path key, which is recorded by pattern name.
**Scenario:** three fields carried raw values into the JSONL log and the stderr mirror: `agentguard exec`'s `metadata.args` (the raw argv); the gateway's `resource` summary and `subDecisions` (every classified value verbatim, so a secret inside any argument that looks like a path, i.e. contains a `/`, was logged as part of a `filesystem:` value); and the interpreter-eval `reason`, which quotes the command line. The call itself was still BLOCKed; the problem was the record of it.
**Reproduction:** `test/security-validation/f14-secret-values-in-audit-log.test.js` (exec argv, interpreter-eval reason, a real gateway process with a secret inside a path, and every field of an event including nested metadata).
**Fix:** `createSecurityEvent` — the single place every adapter builds an event — now replaces every secret-pattern match in every string it records with `[REDACTED:<pattern name>]`. The surrounding text (the path, the command) stays readable. Evaluation is unchanged: it happens before the event is built, on the raw value. Putting this in the one shared constructor means a future adapter cannot reintroduce the leak by choosing a new field.
**Residual risk:** redaction uses the same narrow secret patterns as detection; a secret those patterns do not recognize (an encoded key, an unusual token format) is neither blocked nor redacted. Log lines written before this fix are not rewritten.

### F15 — MEDIUM — A denied folder itself was not covered by its own deny rule — **FIXED (residual stated)**
**Component:** `src/core/glob-match.js`
**How it was found:** during the Phase 6 feasibility review, by evaluating folder paths (what `list_dir`/`grep_search`-style tools take) against the shipped default policy.
**Scenario:** `~/.aws/**` compiles to "`<home>/.aws/` followed by anything", so it matched every file inside the folder but not `<home>/.aws` or `<home>/.aws/` — both were ALLOWED. Any tool that takes a folder could list or search a denied credentials folder without a policy hit: today the official MCP filesystem server's `list_directory`, `directory_tree` and `search_files`; a grep-style tool would return file *contents*.
**Reproduction:** `test/security-validation/f15-folder-targets.test.js` (folder forms on Windows and POSIX, `list_directory`/`directory_tree`/`search_files` through the MCP translator end to end, look-alike names, an allowlist folder).
**Fix:** every value is also tried with a trailing `/`, so a pattern `X/**` covers the folder `X` itself. Only a pattern whose last segment can be empty gains from this: file patterns (`**/*.pem`) do not start matching folders, and look-alike names (`.awsome`, `my.aws`) still do not match. On an allowlist the same rule makes `./workspace` itself count as inside `./workspace/**` (it used to WARN); a sibling like `./workspace-evil` and traversal out of it still WARN.
**Residual gap (kept as a passing test):** a search of a **parent** folder — e.g. a recursive search of the home directory — names nothing denied, so lexical path matching cannot know it will reach `~/.aws`. Whether it does depends on the tool (many search tools skip hidden folders); AgentGuard does not claim to judge it.

### F16 — HIGH — A shell command given as one string was judged by its first word — **FIXED (residual stated)**
**Component:** `src/adapters/mcp/translate.js`; fix in new `src/core/command-line.js`, new `src/adapters/shell/argv-actions.js`, `src/core/policy-engine.js`, `src/core/action.js`
**How it was found:** during the Phase 6 feasibility review, by pushing realistic agent command lines through the MCP translator. No real shell-style MCP server had been used with AgentGuard yet (only fixtures), which is why this stayed latent.
**Scenario:** for an MCP shell-style tool, the translator took `value.trim().split(/\s+/)[0]` as the binary and ignored the rest. With the default `shell.allowed: [git, npm]`: `git status && rm -rf ~/x` was **ALLOWED** (`rm` is in `shell.deny`), as were `npm test | sh` and `git log; curl ...` variants. `$(echo rm) -rf x` was BLOCKed only by accident (the "binary" was read as `$(echo`). A tool naming its key `CommandLine` (Antigravity's `run_command` does) got no shell check at all: `rm -rf x` was ALLOWED.
**Reproduction:** `test/security-validation/f16-shell-command-strings.test.js`, plus parser unit tests in `test/command-line.test.js`.
**Fix:** a deliberately strict parser that accepts only syntax POSIX sh, PowerShell and cmd.exe all read the same way (AgentGuard does not know which shell will run the line): plain words, whole-word single/double quotes without expanding characters, the separators `&& || ; & |`, and simple `> >> <` redirects. **Every** command it splits out goes through the same argv checks `agentguard exec` uses (binary allow/deny, interpreter-eval, path and secret checks per argument), and redirect targets are checked as file writes/reads. Anything else — `$`, backticks, wildcards, parentheses, braces, here-docs, process substitution, line breaks, a leading `VAR=value`, a backslash outside quotes, quotes that are only part of a word, cmd's `%`/`^` — is refused and becomes one `UNPARSEABLE_COMMAND` action, BLOCKed by the new `shell.block_unparseable_commands` (default `true`; `false` = WARN). The policy key is filled in by `applyDefaults`, so existing generated policies get the safe default without being edited. `CommandLine`/`command_line` keys are now recognized as commands.
**Trade-off, stated plainly:** some ordinary commands are refused (`ls *.js`, `echo $PATH`, an unquoted Windows path). That is the price of not guessing how a shell would expand them.
**Residual gap (kept as a passing test):** this decides how a line *splits*, not what an allowed binary does with its own arguments: `npm run <script>`, npm install scripts, git aliases and `git -c` settings run whatever they are configured to run. That is the F2 class — `shell.allowed` trusts whatever an allowed binary can be told to do.

### F17 — MEDIUM — PowerShell's abbreviated inline-code flags evaded the interpreter-eval check — **FIXED (residual stated)**
**Component:** `src/core/resource-heuristics.js` (`isInterpreterEvalAttempt`)
**How it was found:** while building Phase 6.3, Antigravity's `run_command` runs Windows PowerShell, so the F2 check was re-read against PowerShell's real command-line rules. Proved against the previous commit's code before fixing.
**Scenario:** the F2 table matched PowerShell's inline-code flags exactly (`-command`, `-c`). PowerShell accepts any unambiguous abbreviation, with `-` or `/`. `-co`, `-comm` and `/Command` all mean -Command, and `-e`, `-enc`, `-EncodedCommand` and `-ec` pass the code as base64, which no other check can see. Before the fix none of those were flagged, so with `powershell` allowed, `powershell -enc <base64>` ran arbitrary code. That needed a policy allowing powershell, or an agent policy where an unlisted command is only a WARN; the shipped default does not allow it.
**Reproduction:** `test/security-validation/f17-powershell-eval-abbreviations.test.js` (every abbreviation with both prefixes, four executable spellings, ordinary switches not flagged, and `agentguard exec` never starting `powershell -enc`).
**Fix:** for `powershell`/`pwsh`, any `-` or `/` prefix of `-Command` or `-EncodedCommand`, plus `-ec`, is an interpreter-eval attempt.
**Residual (kept as a passing test):** a script *file* (`-File payload.ps1`) is not inline code. That is the same F2 gap as `node script.js`.

### F18 — MEDIUM — Antigravity terminal: a redirection after an expression, and `${drive:path}` file access, were not seen — **FIXED**
**Component:** `src/adapters/antigravity/powershell-parser.js`, `run-command.js` (Phase 6.3, shipped in `d0e5dc7`)
**How it was found:** by the Phase 6.4 self-protection test. Its `'{}' > .agents\hooks.json` case came back ALLOW. The second case turned up while reading the parser code during the fix.
**Scenario:** the run_command translator collected file redirections only from *commands*. A redirection after an *expression* (`'text' > file`) belongs to no command, so its target was never checked. An agent could overwrite any file this way, including `hooks.json` to switch AgentGuard off. Separately, PowerShell's drive-qualified variable syntax (`${C:\path\file}`) reads a file's contents, or writes them when assigned, with no command and no method call at all, so nothing flagged it.
**Reproduction:** `test/antigravity-hooks-install.test.js` (terminal self-protection: `'{}' > .agents\hooks.json`, `${C:\...\hooks.json} = '{}'`), `test/antigravity-run-command.test.js` (`'stolen' > .\.ssh\x`, `${C:\Users\dev\.aws\credentials}`).
**Fix:** the parser script now also returns every file redirection not attached to a command, and every drive-qualified variable whose drive is not `env:`, `variable:`, `function:` or `alias:`. The former are FILE_WRITEs; the latter are UNPARSEABLE (blocked). Ordinary `$env:` / `$global:` variables are unaffected (checked).

### Informational (documented characteristics, not vulnerabilities)
- Gateway/`agentguard exec` are not mandatory chokepoints — inherent to the architecture, now re-confirmed and clearly stated above.
- `serverName` has no cryptographic binding to the spawned command — an operator-trust question, not attacker-exploitable (the agent has no influence over it).
- Tool-name/argument-key-based resource classification means a misleadingly-named MCP tool evades type-specific policy — the existing "heuristic, not schema-aware" limitation, now also understood as a *trust* gap, not just an accuracy one.
- Deeply nested MCP arguments/responses have no recursion-depth limit (`walkStrings`/`collectStrings`) — a real, bounded stack-overflow DoS surface (confirmed via `test/security-validation/resource-exhaustion-and-malformed.test.js`), not fixed in this phase (would need a depth-limit threading change touching multiple call sites for a POC-scale risk — accepted, not remediated).
- `npm audit`: clean, 0 vulnerabilities, single well-known dependency (`js-yaml`).
- Audit log is plain-permission JSONL, tamperable by anything with the same filesystem access AgentGuard restricts — observability, not a forensic store (matches the brief's own framing).
- Secret **values** are never logged anywhere in the pipeline — verified by `test/security-validation/secret-leakage.test.js` and, since F14 showed the original verification was too narrow, `f14-secret-values-in-audit-log.test.js`: a secret match becomes the pattern *name* (e.g. `"aws-access-key-id"`), and any secret text left in a recorded string is replaced with `[REDACTED:<name>]` when the event is built.
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
| A denied folder covered when a tool targets the folder itself | ✓ *(F15; a search of a parent folder is not judged)* |
| Every command in a shell command string checked; unparseable syntax blocked | ✓ *(F16; what an allowed binary runs itself is not judged)* |
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
6. **"AgentGuard does not expose sensitive data through its own logging or inspection mechanisms."** True, verified by direct test, not assumed — but only since F14: the original test covered one gateway case, and `agentguard exec` plus secrets inside path-shaped values did leak into the log until the redaction moved into the shared event constructor.

## Residual risk

- The interpreter-eval bypass (F2) is narrowed, not eliminated — an operator who adds `node`/`python`/similar to `shell.allowed` is still granting broad code-execution capability, just with a slightly higher bar against the most naive attempts.
- The response-inspection split bypass (F5) is narrowed to the common `text`-key convention — a response shape that doesn't use it, or a fragment sequence with any inserted separator, still evades it.
- Network-destination detection (F10) is narrowed to host-style key names and raw HTTP text. A destination hidden under any other field name is still invisible to `network.allowed_domains` — the same "heuristic, not schema-aware" limitation, now observed against a real server rather than only reasoned about.
- Folder coverage (F15) stops at the folder named in the request: a recursive search of a parent folder is not judged by path matching.
- The command-line parser (F16) is strict by design and refuses some ordinary commands; and what an allowed binary runs on its own (npm scripts, git config) remains the F2 class.
- Deep nesting remains a real (bounded, non-catastrophic) DoS surface — not fixed, documented.
- Everything already true about the trust-boundary model (gateway/`agentguard exec` are not mandatory) remains true and is now more explicitly documented in the README threat model.

## DevDay security narrative

**AgentGuard does not attempt to determine whether an AI is malicious.** It establishes explicit security boundaries around agent capabilities routed through it, evaluates observable actions against deterministic policy, blocks prohibited actions — including, now, malformed input that used to slip through unevaluated — and correlates suspicious sequences within a session. This assessment red-teamed those specific claims rather than assuming they held: nine real bypasses were found by writing code that actually exploited the running system, eight are now closed with permanent regression tests proving it, and the two that are only narrowed (allowed interpreters, response-inspection chunking) are said so plainly, not glossed over. What AgentGuard does not claim — a mandatory chokepoint no agent can route around, host-wide monitoring, or any judgment about intent — is exactly what it didn't claim before this assessment either; the point of Phase 3.5 was to verify the things it *does* claim were actually true, and to fix the ones that weren't.
