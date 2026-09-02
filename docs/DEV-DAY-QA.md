# Judge Q&A

Short, honest answers. If a question isn't here, the honest-answer instinct
that produced these is the thing to reuse, not a script to follow rigidly.

**"Is this an EDR?"**
No. AgentGuard is intentionally a lightweight agent security gateway, not
a host EDR. Its enforcement applies at explicit agent/MCP execution
boundaries — not to every process or file operation on the machine.

**"Can't the agent just bypass it?"**
Yes, if it's configured to talk to an MCP server directly, or to run
commands outside the `agentguard exec` boundary. Mandatory mediation (an
agent literally cannot route around it) is a future deployment problem —
OS-level enforcement — not something we claim to solve today. We verified
this ourselves adversarially rather than asserting it; see
`SECURITY-ASSESSMENT.md`.

**"How do you detect prompt injection?"**
We don't claim to semantically detect it. We pattern-match a narrow set of
injection-*shaped* phrases in MCP responses as a detection signal — and,
more importantly, we enforce policy on the *actions* that might result
from an untrusted instruction, regardless of whether we noticed the
instruction itself.

**"Why not use an LLM to detect attacks?"**
Deterministic enforcement is easier to explain, test, and trust for a
security boundary — every decision in this system traces to an explicit
rule you can read in the policy file. An LLM-based signal could be an
*additional* input later; it isn't the enforcement foundation, on purpose.

**"Can it monitor every command on my laptop?"**
No, not without OS-level instrumentation (ptrace, ETW, EndpointSecurity),
which is deliberately out of scope for this lightweight POC. It monitors
what's routed through its two entry points: MCP traffic through the
gateway, and commands through `agentguard exec`.

**"Why MCP specifically?"**
MCP is becoming a common capability interface between agents and tools —
it gives us a natural, protocol-level enforcement boundary, similar to how
an API gateway sits in front of application traffic instead of trying to
instrument every service individually.

**"What makes this different from a vulnerability scanner?"**
A scanner tells you what the environment looks like — installed software,
exposed ports, sensitive files sitting around. AgentGuard does that too
(`agentguard scan`), but it *also* evaluates runtime actions as they
happen and can prevent a prohibited one before it executes. Posture is
"what could happen"; the gateway is "what's actually happening" — we keep
those two concepts deliberately separate rather than merging them into one
score.

**"Did you actually test this against attacks, or just write unit tests?"**
Both, and we treat them as different things. Phase 3.5 was an adversarial
self-assessment: for each hypothesis about how the system might be
bypassed, we wrote a real test that exploited the running code, not just
one that asserted intended behavior. Nine real bypasses were found this
way — malformed JSON silently skipping all policy evaluation was the
worst one — eight are now fixed with permanent regression tests, and the
two that are only narrowed (an allowed interpreter's `-e` flag, response
inspection across split fragments) are documented as narrowed, not
claimed as solved. Full writeup: `SECURITY-ASSESSMENT.md`.

**"What's the biggest thing this doesn't protect against?"**
That it isn't a mandatory boundary — see the bypass question above — and
that an "allowed" general-purpose interpreter (node, python, a shell) is
close to unrestricted code execution no matter what else the policy says,
because policy only ever inspects the top-level command. We added a narrow
mitigation for the most obvious case (`-e`/`-c` flags) and say plainly that
it doesn't close the underlying problem.

**"What happens if the policy file itself is wrong or missing?"**
A malformed policy file fails to load and the gateway/exec command exits
immediately with an error — it does not start up in some silently-permissive
default state. Missing sections in an otherwise-valid policy file get safe
defaults (documented in `policy/default-policy.yaml`); an unrecognized
resource type internally now WARNs rather than silently allowing, so a
future code change can't accidentally regress to fail-open.

**"Is the audit log tamper-proof?"**
No, and we say so directly: it's a plain-permission JSONL file, readable
and writable by anything with the same filesystem access AgentGuard itself
restricts. It's an observability mechanism, not a forensic-grade store.

**"What's next / what would you build if you had another month?"**
In priority order: real network enforcement (an OS-level proxy instead of
best-effort URL-argument inspection), HTTP/SSE MCP transport (deliberately
deferred — separate transport plumbing, not core to the security story),
and a real cross-adapter identity so a gateway session and an
`agentguard exec` run by the same agent correlate as one instead of two.
