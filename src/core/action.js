/**
 * An Action is the transport-agnostic unit the PolicyEngine evaluates.
 * MCP is one *source* of actions; a future shell/filesystem/network adapter
 * would produce the same shape so the engine never needs to know MCP exists.
 *
 * @typedef {'filesystem'|'shell'|'mcp-server'|'network'|'secret'|'interpreter-eval'} ResourceType
 *
 * @typedef {Object} Action
 * @property {string} verb                 - e.g. 'read', 'execute', 'invoke', 'transmit'
 * @property {string} actionType            - one of ActionType, derived from resourceType+verb
 * @property {{type: ResourceType, value: string}} resource
 * @property {Object} context               - source, sessionId, toolName, serverName, method, timestamp
 */

/**
 * Only the action shapes this system can actually observe get an entry
 * here. Do not add a type unless something in src/adapters produces it —
 * an enum value nothing ever emits is a false claim of capability.
 */
export const ActionType = Object.freeze({
  MCP_TOOL_CALL: 'MCP_TOOL_CALL',
  FILE_READ: 'FILE_READ',
  FILE_WRITE: 'FILE_WRITE',
  SHELL_EXEC: 'SHELL_EXEC',
  NETWORK_REQUEST: 'NETWORK_REQUEST',
  // Not a resource-access verb like the others above; a cross-cutting
  // pattern match against any tool-call argument. Kept distinct rather
  // than forced into the list above.
  SECRET_PATTERN_MATCH: 'SECRET_PATTERN_MATCH',
  // Same idea: a known interpreter invoked with an inline-eval flag,
  // detected alongside (not instead of) the ordinary SHELL_EXEC action for
  // the same call. See SECURITY-ASSESSMENT.md F2.
  INTERPRETER_EVAL_ATTEMPT: 'INTERPRETER_EVAL_ATTEMPT',
});

const TYPE_BY_RESOURCE_VERB = {
  'mcp-server:invoke': ActionType.MCP_TOOL_CALL,
  'filesystem:read': ActionType.FILE_READ,
  'filesystem:write': ActionType.FILE_WRITE,
  'shell:execute': ActionType.SHELL_EXEC,
  'network:network': ActionType.NETWORK_REQUEST,
  'secret:transmit': ActionType.SECRET_PATTERN_MATCH,
  'interpreter-eval:execute': ActionType.INTERPRETER_EVAL_ATTEMPT,
};

/** @returns {Action} */
export function createAction({ verb, resourceType, resourceValue, context }) {
  return {
    verb,
    actionType: TYPE_BY_RESOURCE_VERB[`${resourceType}:${verb}`] ?? null,
    resource: { type: resourceType, value: resourceValue },
    context,
  };
}
