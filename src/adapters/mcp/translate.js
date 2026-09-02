import { createAction } from '../../core/action.js';

const PATH_KEY_RE = /path|file|dir|directory|target|cwd|location|filename/i;
const SHELL_TOOL_RE = /shell|exec|command|run_cmd|terminal|bash|powershell|^cmd$/i;
const SHELL_KEY_RE = /^(command|cmd|script)$/i;
const URL_RE = /^[a-z][a-z0-9+.-]*:\/\//i;
// Best-effort only: we don't know each server's tool schema, so a tool name
// is the only signal available for read vs write. Defaults to read (FILE_READ
// is far more common among MCP filesystem tools) rather than over-claiming.
const WRITE_TOOL_RE = /write|create|append|delete|remove|unlink|rm|update|edit|save|rename|move|mkdir/i;

// Deliberately narrow, high-confidence patterns. This is a heuristic scan of
// tool-call arguments, not a general-purpose DLP engine (see README limitations).
const SECRET_PATTERNS = [
  { name: 'aws-access-key-id', re: /AKIA[0-9A-Z]{16}/ },
  { name: 'private-key-block', re: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { name: 'generic-secret-assignment', re: /(api[_-]?key|secret|token)["']?\s*[:=]\s*["'][A-Za-z0-9/+_-]{20,}["']/i },
];

function looksLikePath(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  if (value.startsWith('~')) return true;
  if (/^[a-zA-Z]:[\\/]/.test(value)) return true; // C:\ or C:/
  if (value.startsWith('/') || value.startsWith('./') || value.startsWith('../')) return true;
  if (value.includes('/') || value.includes('\\')) return true;
  return false;
}

function extractHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

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
