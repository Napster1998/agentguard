import { applyDefaults } from '../../core/policy-engine.js';
import { createPosture } from '../../core/security-posture.js';
import { resetFindingCounters } from '../../core/security-finding.js';
import * as rules from '../../core/findings-rules.js';

import { detectAgents } from './agent-detection.js';
import { discoverMcpServers, knownConfigLocations } from './mcp-config.js';
import { assessNetworkExposure } from './network-exposure.js';
import { scanSensitiveResources } from './sensitive-resources.js';

/**
 * Runs the full DISCOVER -> ASSESS pass and returns a SecurityPosture.
 *
 * Read-only, by design: never modifies a file, never executes a discovered
 * MCP server command, never reads a sensitive resource's contents (only
 * existence/permissions), never makes an external network call (only
 * inspects this machine's own socket table).
 */
export async function runScan({ policy = applyDefaults({}), cwd = process.cwd() } = {}) {
  resetFindingCounters();

  const discoveredAgents = await detectAgents();
  const { servers: discoveredMcpServers, errors: mcpErrors } = discoverMcpServers({
    locations: knownConfigLocations({ cwd }),
    trustedServerNames: policy.mcp.allowed_servers,
  });
  const exposedServices = await assessNetworkExposure({ detectedAgents: discoveredAgents });
  const sensitiveResources = scanSensitiveResources({ cwd });

  const findings = [
    ...rules.agentFindings(discoveredAgents),
    ...rules.networkFindings(exposedServices),
    ...rules.mcpFindings({ servers: discoveredMcpServers, errors: mcpErrors }),
    ...rules.sensitiveResourceFindings(sensitiveResources),
  ];

  return createPosture({
    discoveredAgents,
    discoveredMcpServers,
    exposedServices,
    sensitiveResources,
    findings,
  });
}
