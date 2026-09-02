/**
 * An Action is the transport-agnostic unit the PolicyEngine evaluates.
 * MCP is one *source* of actions; a future shell/filesystem/network adapter
 * would produce the same shape so the engine never needs to know MCP exists.
 *
 * @typedef {'filesystem'|'shell'|'mcp-server'|'network'|'secret'} ResourceType
 *
 * @typedef {Object} Action
 * @property {string} verb                 - e.g. 'read', 'execute', 'invoke', 'transmit'
 * @property {{type: ResourceType, value: string}} resource
 * @property {Object} context               - source, sessionId, toolName, serverName, method, timestamp
 */

/** @returns {Action} */
export function createAction({ verb, resourceType, resourceValue, context }) {
  return {
    verb,
    resource: { type: resourceType, value: resourceValue },
    context,
  };
}
