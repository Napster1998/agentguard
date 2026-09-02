import { createFinding } from './security-finding.js';

/**
 * Pure functions turning raw discovery output into SecurityFinding[]. Kept
 * separate from the discovery adapters themselves so the *rule* ("an
 * externally-bound AI service is a HIGH finding") lives in one place
 * instead of being duplicated per adapter.
 */

export function agentFindings(_detectedAgents) {
  // Detecting an agent is not itself a finding — only what it exposes is
  // (see networkFindings/sensitiveResourceFindings). Kept as an explicit
  // seam: a future rule like "agent running with no gateway configured"
  // belongs here.
  return [];
}

export function networkFindings(exposures) {
  return exposures
    .filter((e) => e.externallyBound)
    .map((e) =>
      createFinding({
        category: 'network',
        title: `${e.label} exposed beyond localhost`,
        severity: 'HIGH',
        description: `${e.label} is listening on an address other than localhost, making it potentially reachable from other machines on the network.`,
        evidence: `${e.label} listening on ${e.host}:${e.port}`,
        recommendation: 'Bind the service to localhost (127.0.0.1) unless remote access is explicitly required.',
      })
    );
}

export function mcpFindings({ servers, errors }) {
  const findings = errors.map((e) =>
    createFinding({
      category: 'mcp',
      title: 'MCP configuration could not be parsed',
      severity: 'LOW',
      description: 'A discovered MCP client configuration file is not valid JSON and was skipped.',
      evidence: `${e.location}: ${e.message}`,
      recommendation: 'Fix or remove the malformed configuration file.',
    })
  );

  for (const server of servers) {
    if (server.trust === 'unknown') {
      findings.push(
        createFinding({
          category: 'mcp',
          title: `Untrusted MCP server "${server.name}" configured`,
          severity: 'MEDIUM',
          description: "This MCP server is configured but is not present in the gateway policy's mcp.allowed_servers list.",
          evidence: `${server.name} (${server.transport}) in ${server.configLocation}`,
          recommendation: `Add "${server.name}" to mcp.allowed_servers if it is trusted, or remove it if it is not needed.`,
        })
      );
    }
  }

  return findings;
}

export function sensitiveResourceFindings(resources) {
  return resources.map((r) =>
    createFinding({
      category: 'filesystem',
      title: `${r.label} is present and potentially agent-accessible`,
      severity: r.severity,
      description: `${r.label} exists on this machine. If an AI agent's filesystem access is not scoped away from it, the agent can read it.`,
      evidence: `${r.path} (${r.isDirectory ? 'directory' : 'file'}, mode ${r.mode})`,
      recommendation:
        r.severity === 'CRITICAL'
          ? 'Ensure agent tooling never has filesystem access to this path; add it to filesystem.deny in the gateway policy.'
          : 'Scope agent filesystem access away from this path, or add it to filesystem.deny/warn in the gateway policy.',
    })
  );
}
