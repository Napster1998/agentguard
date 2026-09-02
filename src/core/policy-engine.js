import { VERDICT, makeDecision } from './decision.js';
import { RISK } from './risk.js';
import { matchesAny } from './glob-match.js';
import { assessRisk } from './risk-engine.js';

const EXECUTABLE_EXTENSIONS = /\.(exe|cmd|bat|com|ps1)$/i;

/**
 * Normalizes a shell binary reference to its basename with a common
 * Windows executable extension stripped, so `shell.allowed`/`shell.deny`
 * match "rm", "/bin/rm", "rm.exe", and "RM.EXE" consistently — see
 * SECURITY-ASSESSMENT.md F3. Both the incoming command AND each policy
 * list entry are normalized the same way, so a policy author can write
 * either form.
 */
function normalizeBinary(binary) {
  const basename = binary.replace(/\\/g, '/').split('/').pop() || binary;
  return basename.toLowerCase().replace(EXECUTABLE_EXTENSIONS, '');
}

/**
 * Fills in missing policy sections so a partial/minimal policy file never
 * crashes the engine. Documented defaults:
 *  - filesystem.allow empty  -> no allowlist restriction (deny/warn still apply)
 *  - shell.allowed empty     -> ALL shell-tool commands are blocked (secure by default)
 *  - shell.deny              -> checked BEFORE shell.allowed and always wins,
 *                                even for a binary also present in shell.allowed
 *  - shell.block_interpreter_eval defaults to true — BLOCKs a known
 *                                interpreter (node/python/sh/powershell/...)
 *                                invoked with an inline-code flag (-e/-c/
 *                                -Command/...), even if that interpreter is
 *                                itself in shell.allowed. See F2 in
 *                                SECURITY-ASSESSMENT.md: shell.allowed only
 *                                inspects the binary name, so a general-
 *                                purpose interpreter otherwise grants
 *                                arbitrary code execution.
 *  - mcp.allowed_servers empty -> all MCP servers are trusted (no reputation data yet)
 *  - network.allowed_domains empty -> no domain restriction (best-effort visibility only)
 *  - secrets.block_exfiltration defaults to true
 *  - mcp_response_inspection.block_on_secret_pattern defaults to true (mirrors
 *    the request-side default); block_on_suspicious_instruction defaults to
 *    false (log-only — pattern-matching a response is a detection signal,
 *    not proof, so blocking on it is opt-in)
 */
export function applyDefaults(raw = {}) {
  return {
    filesystem: { allow: [], deny: [], warn: [], ...raw.filesystem },
    shell: { allowed: [], deny: [], block_interpreter_eval: true, ...raw.shell },
    mcp: { allowed_servers: [], ...raw.mcp },
    network: { allowed_domains: [], ...raw.network },
    secrets: { block_exfiltration: true, ...raw.secrets },
    mcp_response_inspection: {
      block_on_secret_pattern: true,
      block_on_suspicious_instruction: false,
      ...raw.mcp_response_inspection,
    },
  };
}

export class PolicyEngine {
  constructor(policy) {
    this.policy = policy;
  }

  /** @returns {{verdict: string, reason: string, risk: string, rule: string|null}} */
  evaluate(action) {
    switch (action.resource.type) {
      case 'filesystem':
        return this.#evaluateFilesystem(action);
      case 'shell':
        return this.#evaluateShell(action);
      case 'interpreter-eval':
        return this.#evaluateInterpreterEval(action);
      case 'mcp-server':
        return this.#evaluateMcpServer(action);
      case 'network':
        return this.#evaluateNetwork(action);
      case 'secret':
        return this.#evaluateSecret(action);
      default:
        // Fail SAFE, not open: an unrecognized resource type means "we
        // don't know how to evaluate this," not "allow it." Not reachable
        // via any current adapter (all of which only ever produce the
        // types handled above) — this exists for whatever adapter comes
        // next, so it can't silently regress to unconditional ALLOW.
        return makeDecision({
          verdict: VERDICT.WARN,
          reason: `No policy rule exists for resource type "${action.resource.type}"; flagged rather than silently allowed.`,
          risk: assessRisk({ sensitivity: RISK.MEDIUM, verdict: VERDICT.WARN }),
          rule: null,
        });
    }
  }

  #evaluateFilesystem(action) {
    const { value } = action.resource;
    const { deny, warn, allow } = this.policy.filesystem;

    const deniedBy = matchesAny(value, deny);
    if (deniedBy) {
      const verdict = VERDICT.BLOCK;
      return makeDecision({
        verdict,
        reason: `Path matches a denied pattern in filesystem.deny ("${deniedBy}"); credential/sensitive paths are not accessible to agents.`,
        risk: assessRisk({ sensitivity: RISK.CRITICAL, verdict }),
        rule: 'filesystem.deny',
      });
    }

    const warnedBy = matchesAny(value, warn);
    if (warnedBy) {
      const verdict = VERDICT.WARN;
      return makeDecision({
        verdict,
        reason: `Path matches a watched pattern in filesystem.warn ("${warnedBy}"); often legitimate but flagged for review.`,
        risk: assessRisk({ sensitivity: RISK.HIGH, verdict }),
        rule: 'filesystem.warn',
      });
    }

    if (allow && allow.length > 0 && !matchesAny(value, allow)) {
      const verdict = VERDICT.WARN;
      return makeDecision({
        verdict,
        reason: 'Path is outside the configured filesystem.allow allowlist.',
        risk: assessRisk({ sensitivity: RISK.LOW, verdict }),
        rule: 'filesystem.allow',
      });
    }

    const verdict = VERDICT.ALLOW;
    return makeDecision({
      verdict,
      reason: 'Path does not match any deny/warn rule.',
      risk: assessRisk({ sensitivity: RISK.LOW, verdict }),
      rule: 'filesystem.allow',
    });
  }

  #evaluateShell(action) {
    const { value: binary } = action.resource;
    const { allowed, deny } = this.policy.shell;
    const normalizedBinary = normalizeBinary(binary);

    if (deny.some((d) => normalizeBinary(d) === normalizedBinary)) {
      const verdict = VERDICT.BLOCK;
      return makeDecision({
        verdict,
        reason: `Command "${binary}" is explicitly denied by shell.deny.`,
        risk: assessRisk({ sensitivity: RISK.HIGH, verdict }),
        rule: 'shell.deny',
      });
    }

    if (allowed.some((a) => normalizeBinary(a) === normalizedBinary)) {
      const verdict = VERDICT.ALLOW;
      return makeDecision({
        verdict,
        reason: `Command "${binary}" is in shell.allowed.`,
        risk: assessRisk({ sensitivity: RISK.LOW, verdict }),
        rule: 'shell.allowed',
      });
    }

    const verdict = VERDICT.BLOCK;
    return makeDecision({
      verdict,
      reason: `Command "${binary}" is not in the shell.allowed allowlist. Arbitrary shell execution is blocked by default.`,
      risk: assessRisk({ sensitivity: RISK.MEDIUM, verdict }),
      rule: 'shell.allowed',
    });
  }

  /**
   * shell.allowed only ever inspects the top-level binary — an allowed
   * general-purpose interpreter (node/python/sh/powershell/...) invoked
   * with an inline-code flag grants arbitrary code execution regardless of
   * what shell.allowed says. This BLOCKs that specific, narrow pattern by
   * default, independent of whether the interpreter itself is allowed —
   * see SECURITY-ASSESSMENT.md F2. Configurable off via
   * shell.block_interpreter_eval for a deployment that has already
   * accepted this risk.
   */
  #evaluateInterpreterEval(action) {
    if (!this.policy.shell.block_interpreter_eval) {
      const verdict = VERDICT.WARN;
      return makeDecision({
        verdict,
        reason: `Command "${action.resource.value}" invokes an interpreter with an inline-code flag; shell.block_interpreter_eval is disabled, so this is flagged rather than blocked.`,
        risk: assessRisk({ sensitivity: RISK.HIGH, verdict }),
        rule: 'shell.block_interpreter_eval',
      });
    }

    const verdict = VERDICT.BLOCK;
    return makeDecision({
      verdict,
      reason: `Command "${action.resource.value}" invokes a general-purpose interpreter with an inline-code flag (e.g. -e/-c/-Command); this would bypass shell.allowed's binary-name-only enforcement, so it is blocked by default regardless of whether the interpreter itself is allowed.`,
      risk: assessRisk({ sensitivity: RISK.CRITICAL, verdict, credentialInvolved: true }),
      rule: 'shell.block_interpreter_eval',
    });
  }

  #evaluateMcpServer(action) {
    const { value: serverName } = action.resource;
    const { allowed_servers: allowedServers } = this.policy.mcp;

    if (allowedServers.length === 0 || allowedServers.includes(serverName)) {
      const verdict = VERDICT.ALLOW;
      return makeDecision({
        verdict,
        reason:
          allowedServers.length === 0
            ? 'No mcp.allowed_servers restriction configured.'
            : `Server "${serverName}" is in mcp.allowed_servers.`,
        risk: assessRisk({ sensitivity: RISK.LOW, verdict }),
        rule: 'mcp.allowed_servers',
      });
    }

    const verdict = VERDICT.WARN;
    return makeDecision({
      verdict,
      reason: `Server "${serverName}" is not in the mcp.allowed_servers trusted list.`,
      risk: assessRisk({ sensitivity: RISK.MEDIUM, verdict }),
      rule: 'mcp.allowed_servers',
    });
  }

  #evaluateNetwork(action) {
    const { value: hostname } = action.resource;
    const { allowed_domains: allowedDomains } = this.policy.network;

    const isAllowed =
      allowedDomains.length === 0 ||
      allowedDomains.some(
        (d) => hostname === d || hostname.endsWith(`.${d}`)
      );

    if (isAllowed) {
      const verdict = VERDICT.ALLOW;
      return makeDecision({
        verdict,
        reason:
          allowedDomains.length === 0
            ? 'No network.allowed_domains restriction configured.'
            : `Domain "${hostname}" is in network.allowed_domains.`,
        risk: assessRisk({ sensitivity: RISK.LOW, verdict }),
        rule: 'network.allowed_domains',
      });
    }

    const verdict = VERDICT.WARN;
    return makeDecision({
      verdict,
      reason: `Domain "${hostname}" is not in network.allowed_domains. (Best-effort: only domains visible in MCP tool-call arguments can be checked.)`,
      risk: assessRisk({ sensitivity: RISK.MEDIUM, verdict }),
      rule: 'network.allowed_domains',
    });
  }

  #evaluateSecret(action) {
    if (!this.policy.secrets.block_exfiltration) {
      const verdict = VERDICT.ALLOW;
      return makeDecision({
        verdict,
        reason: 'secrets.block_exfiltration is disabled.',
        risk: assessRisk({ sensitivity: RISK.NONE, verdict }),
        rule: 'secrets.block_exfiltration',
      });
    }

    const verdict = VERDICT.BLOCK;
    return makeDecision({
      verdict,
      reason: `Argument value matches a known secret pattern ("${action.resource.value}"); possible credential exfiltration.`,
      risk: assessRisk({ sensitivity: RISK.CRITICAL, verdict, credentialInvolved: true }),
      rule: 'secrets.block_exfiltration',
    });
  }
}
