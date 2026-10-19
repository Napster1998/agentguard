import { createAction } from '../../core/action.js';
import {
  PATH_KEY_RE,
  NETWORK_KEY_RE,
  URL_RE,
  WRITE_TOOL_RE,
  SECRET_PATTERNS,
  looksLikePath,
  extractHostname,
  parseBareHostname,
  parseRawHttpRequest,
  isInterpreterEvalAttempt,
} from '../../core/resource-heuristics.js';

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

  // One network action per distinct host per call (a tool may name the same
  // destination in several places, e.g. targetHostname AND a Host header).
  const seenHosts = new Set();
  const addNetwork = (host) => {
    if (seenHosts.has(host)) return;
    seenHosts.add(host);
    actions.push(createAction({ verb: 'network', resourceType: 'network', resourceValue: host, context: baseContext }));
  };

  walkStrings(args, (key, value) => {
    if (isShellTool && SHELL_KEY_RE.test(key)) {
      const parts = value.trim().split(/\s+/);
      const binary = parts[0];
      if (binary) {
        actions.push(
          createAction({ verb: 'execute', resourceType: 'shell', resourceValue: binary, context: baseContext })
        );
        if (isInterpreterEvalAttempt(binary, parts.slice(1))) {
          actions.push(
            createAction({ verb: 'execute', resourceType: 'interpreter-eval', resourceValue: value, context: baseContext })
          );
        }
      }
    }

    // Network destinations, in order of specificity: raw HTTP request text
    // (its Host header), a scheme:// URL, then a bare hostname under a
    // host-style key. All checked before the path heuristics so a hostname
    // or HTTP text is never filed as a filesystem path (F10).
    const httpRequest = parseRawHttpRequest(value);
    const bareHost = !httpRequest && !URL_RE.test(value) && NETWORK_KEY_RE.test(key) ? parseBareHostname(value) : null;

    if (httpRequest) {
      httpRequest.hosts.forEach(addNetwork);
    } else if (URL_RE.test(value)) {
      const host = extractHostname(value);
      if (host) addNetwork(host);
    } else if (bareHost) {
      addNetwork(bareHost);
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
