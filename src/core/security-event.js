import crypto from 'node:crypto';

/**
 * The record of one evaluated Action, correlatable by sessionId. This is
 * the single shape written to the JSONL audit log and read back by
 * `agentguard events` — the audit log *is* the event store for Phase 2;
 * see README "Event correlation" for why no separate store was added.
 *
 * @typedef {Object} SecurityEvent
 * @property {string} id
 * @property {string} sessionId    - one gateway connection/run
 * @property {string} agentId      - Phase 1/2 have no identity signal beyond
 *                                    the session itself, so agentId === sessionId
 *                                    today (documented limitation, not a bug)
 * @property {string} timestamp
 * @property {string} source       - 'mcp' today; future adapters add their own
 * @property {string|null} actionType
 * @property {string|null} toolName
 * @property {string|null} serverName
 * @property {string|null} resource - "type:value" summary of every resource involved
 * @property {string} decision      - ALLOW | WARN | BLOCK
 * @property {string} risk
 * @property {string|null} rule
 * @property {string} reason
 * @property {Array<object>} subDecisions
 */

/** @returns {SecurityEvent} */
export function createSecurityEvent({
  sessionId,
  source,
  actionType = null,
  toolName = null,
  serverName = null,
  resource = null,
  decision,
  risk,
  rule = null,
  reason,
  subDecisions = [],
  timestamp = new Date().toISOString(),
}) {
  return {
    id: crypto.randomUUID(),
    sessionId,
    agentId: sessionId,
    timestamp,
    source,
    actionType,
    toolName,
    serverName,
    resource,
    decision,
    risk,
    rule,
    reason,
    subDecisions,
  };
}
