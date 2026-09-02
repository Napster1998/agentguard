import crypto from 'node:crypto';

/**
 * The record of one evaluated Action, correlatable by sessionId. This is
 * the single shape written to the JSONL audit log and read back by
 * `agentguard events` — the audit log *is* the event store; see README
 * "Event correlation" for why no separate store was added.
 *
 * @typedef {Object} SecurityEvent
 * @property {string} id
 * @property {string} sessionId    - one gateway/exec-wrapper connection or run
 * @property {string} agentId      - the strongest identity signal actually
 *                                    available (MCP `initialize`'s clientInfo.name
 *                                    when present); falls back to sessionId when
 *                                    it isn't — see README "Identity" limitation
 * @property {string} timestamp
 * @property {string} source       - 'mcp' | 'shell-exec' — which adapter produced this
 * @property {'request'|'response'} direction - a request-side decision, or an
 *                                    inspected MCP tool-call response
 * @property {string|null} actionType
 * @property {string|null} toolName
 * @property {string|null} serverName
 * @property {string|null} resource - "type:value" summary of every resource involved
 * @property {string|null} destination - e.g. a network hostname, when applicable
 * @property {string} decision      - ALLOW | WARN | BLOCK
 * @property {string} risk
 * @property {string|null} rule
 * @property {string} reason
 * @property {Array<object>} subDecisions
 * @property {object|null} metadata - adapter-specific extra fields (e.g. cwd for shell-exec)
 */

/** @returns {SecurityEvent} */
export function createSecurityEvent({
  sessionId,
  agentId = sessionId,
  source,
  direction = 'request',
  actionType = null,
  toolName = null,
  serverName = null,
  resource = null,
  destination = null,
  decision,
  risk,
  rule = null,
  reason,
  subDecisions = [],
  metadata = null,
  timestamp = new Date().toISOString(),
}) {
  return {
    id: crypto.randomUUID(),
    sessionId,
    agentId,
    timestamp,
    source,
    direction,
    actionType,
    toolName,
    serverName,
    resource,
    destination,
    decision,
    risk,
    rule,
    reason,
    subDecisions,
    metadata,
  };
}
