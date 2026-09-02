import { createAction } from '../../core/action.js';
import { PATH_KEY_RE, URL_RE, WRITE_TOOL_RE, SECRET_PATTERNS, looksLikePath, extractHostname } from '../../core/resource-heuristics.js';

const SHELL_TOOL_RE = /shell|exec|command|run_cmd|terminal|bash|powershell|^cmd$/i;
const SHELL_KEY_RE = /^(command|cmd|script)$/i;

function walkStrings(node, visit, keyPath = []) {
  if (node == null) return;
  if (typeof node === 'string') {
    visit(keyPath[keyPath.length - 1] || '', node);
    return;
  }
  if (Array.isArray(node)) {
    node.forEach((v, i) => walkStrings(v, visit, [...keyPath, String(i)]));
    return;
  }
  if (typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) walkStrings(v, visit, [...keyPath, k]);
  }
}

/**
 * Translates one MCP JSON-RPC request into zero or more generic Actions.
 * Only `tools/call` carries resources worth evaluating; everything else
 * (initialize, tools/list, ping, ...) passes through untouched.
 *
 * @param {object} message   parsed JSON-RPC request
 * @param {object} context   { source, sessionId, serverName }
 * @returns {import('../../core/action.js').Action[]}
 */
export function mcpRequestToActions(message, context) {
  if (message.method !== 'tools/call') return [];

  const params = message.params || {};
  const toolName = params.name || 'unknown';
  const args = params.arguments || {};
  const baseContext = { ...context, toolName, method: message.method };

  const actions = [
    createAction({
      verb: 'invoke',
      resourceType: 'mcp-server',
      resourceValue: context.serverName,
      context: baseContext,
    }),
  ];

  const isShellTool = SHELL_TOOL_RE.test(toolName);
  const filesystemVerb = WRITE_TOOL_RE.test(toolName) ? 'write' : 'read';

  walkStrings(args, (key, value) => {
    if (isShellTool && SHELL_KEY_RE.test(key)) {
      const binary = value.trim().split(/\s+/)[0];
      if (binary) {
        actions.push(
          createAction({ verb: 'execute', resourceType: 'shell', resourceValue: binary, context: baseContext })
        );
      }
    }

    if (URL_RE.test(value)) {
      const host = extractHostname(value);
      if (host) {
        actions.push(
          createAction({ verb: 'network', resourceType: 'network', resourceValue: host, context: baseContext })
        );
      }
    } else if (PATH_KEY_RE.test(key) || looksLikePath(value)) {
      actions.push(
        createAction({ verb: filesystemVerb, resourceType: 'filesystem', resourceValue: value, context: baseContext })
      );
    }

    for (const pattern of SECRET_PATTERNS) {
      if (pattern.re.test(value)) {
        actions.push(
          createAction({ verb: 'transmit', resourceType: 'secret', resourceValue: pattern.name, context: baseContext })
        );
      }
    }
  });

  return actions;
}
