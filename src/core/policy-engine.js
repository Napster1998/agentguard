import { VERDICT, makeDecision } from './decision.js';
import { RISK } from './risk.js';
import { matchesAny } from './glob-match.js';
import { assessRisk } from './risk-engine.js';

/**
 * Fills in missing policy sections so a partial/minimal policy file never
 * crashes the engine. Documented defaults:
 *  - filesystem.allow empty  -> no allowlist restriction (deny/warn still apply)
 *  - shell.allowed empty     -> ALL shell-tool commands are blocked (secure by default)
 *  - mcp.allowed_servers empty -> all MCP servers are trusted (no reputation data yet)
 *  - network.allowed_domains empty -> no domain restriction (best-effort visibility only)
 *  - secrets.block_exfiltration defaults to true
 */
export function applyDefaults(raw = {}) {
  return {
    filesystem: { allow: [], deny: [], warn: [], ...raw.filesystem },
    shell: { allowed: [], ...raw.shell },
    mcp: { allowed_servers: [], ...raw.mcp },
    network: { allowed_domains: [], ...raw.network },
    secrets: { block_exfiltration: true, ...raw.secrets },
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
      case 'mcp-server':
        return this.#evaluateMcpServer(action);
      case 'network':
        return this.#evaluateNetwork(action);
      case 'secret':
        return this.#evaluateSecret(action);
      default:
        return makeDecision({
          verdict: VERDICT.ALLOW,
          reason: 'No policy rule exists for this resource type',
          risk: assessRisk({ sensitivity: RISK.NONE, verdict: VERDICT.ALLOW }),
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
    const { allowed } = this.policy.shell;

    if (allowed.some((a) => a.toLowerCase() === binary.toLowerCase())) {
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
