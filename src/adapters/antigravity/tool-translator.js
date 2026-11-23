import path from 'node:path';

import { createAction } from '../../core/action.js';
import { findSecretMatches } from '../../core/resource-heuristics.js';
import { mcpRequestToActions } from '../mcp/translate.js';
import { runCommandToActions } from './run-command.js';

/**
 * Translates one Antigravity tool call into Actions.
 *
 * Built from the tool names and argument names Antigravity actually sent in
 * the Phase 6 validation spike (identical for Claude Opus, Claude Sonnet and
 * Gemini Flash), NOT from the published tool table, which lists tools this
 * App version does not have (view_file, list_dir, grep_search, ...). Names are
 * matched exactly; extra arguments are tolerated (Gemini adds `Overwrite`).
 *
 * Every string anywhere in the arguments is checked for secret patterns, the
 * same way the MCP gateway checks every tool-call argument. On top of that:
 *   - file tools: the target path is a FILE_READ / FILE_WRITE;
 *   - tools that carry text but touch no resource: secrets only;
 *   - call_mcp_tool{ServerName, ToolName, Arguments}: becomes the MCP request
 *     it stands for and goes through the SAME translator as the MCP gateway
 *     (server allowlist, paths, network destinations, secrets) - unless that
 *     server is already behind the gateway, which then checks it (Phase 6.2);
 *   - run_command{CommandLine, BypassSandbox?}: every command in the line,
 *     read by PowerShell's own parser on Windows (run-command.js, Phase 6.3);
 *   - any other tool: one `agent-tool` action, which the policy engine has no
 *     rule for, so it is WARNed (allowed and logged, never silently trusted).
 */

const FILE_TOOLS = {
  read_file: { verb: 'read', pathArg: 'Path' },
  write_file: { verb: 'write', pathArg: 'Path' },
  edit_file: { verb: 'write', pathArg: 'Path' },
};

// Seen in the spike; they carry text (checked for secrets) but name no file,
// command, URL or server, so there is nothing else to evaluate.
const NO_RESOURCE_TOOLS = new Set([
  'send_message',
  'invoke_subagent',
  'search_web',
  'search_marketplace',
  'list_plugin_accounts',
  'update_focus',
  'update_steps',
  'ask_question',
  'manage_subagents',
]);

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * call_mcp_tool -> the MCP `tools/call` it stands for -> the gateway's own
 * translator, so an MCP call is judged identically whichever way it arrives.
 */
function mcpCallToActions(args, context, isMcpServerWrapped) {
  const server = args.ServerName;
  const tool = args.ToolName;
  if (typeof server !== 'string' || !server || typeof tool !== 'string' || !tool) {
    return { actions: [], error: 'call_mcp_tool was called without a ServerName and ToolName, so the MCP call cannot be checked' };
  }
  if (args.Arguments !== undefined && !isPlainObject(args.Arguments)) {
    return { actions: [], error: `the arguments of the MCP call ${server}/${tool} are not an object, so they cannot be checked` };
  }
  if (isMcpServerWrapped(server)) {
    return { actions: [], skip: `MCP server "${server}" runs behind the AgentGuard gateway, which checks this call` };
  }
  const message = { jsonrpc: '2.0', method: 'tools/call', params: { name: tool, arguments: args.Arguments ?? {} } };
  return { actions: mcpRequestToActions(message, { ...context, serverName: server }), mcp: { server, tool } };
}

function collectStrings(node, out = []) {
  if (typeof node === 'string') out.push(node);
  else if (Array.isArray(node)) node.forEach((v) => collectStrings(v, out));
  else if (node && typeof node === 'object') Object.values(node).forEach((v) => collectStrings(v, out));
  return out;
}

const WINDOWS_PATH_RE = /^[A-Za-z]:[\\/]|^\\\\/;

/**
 * A relative path is resolved against the workspace Antigravity reports. The
 * path style follows the workspace (a Windows workspace resolves Windows-style
 * on any host), so the decision does not depend on where AgentGuard runs.
 */
function resolveTarget(p, cwd) {
  if (p.startsWith('~') || path.posix.isAbsolute(p) || path.win32.isAbsolute(p) || !cwd) return p;
  return (WINDOWS_PATH_RE.test(cwd) ? path.win32 : path.posix).resolve(cwd, p);
}

/**
 * @param {{name: string, args: object}} toolCall
 * @param {{cwd: string|null, context: object, isMcpServerWrapped?: (server: string) => boolean,
 *          shellPolicy?: object, parsePowerShell?: Function, platform?: string, homedir?: string}} opts
 * @returns {{actions: import('../../core/action.js').Action[], error?: string,
 *            skip?: string, mcp?: {server: string, tool: string}}}
 */
export function toolCallToActions(toolCall, opts) {
  const { cwd, context, isMcpServerWrapped = () => false } = opts;
  const { name, args } = toolCall;
  // The MCP translator already secret-scans every string of the MCP arguments.
  if (name === 'call_mcp_tool') return mcpCallToActions(args, context, isMcpServerWrapped);

  const actions = [];

  const file = FILE_TOOLS[name];
  if (file) {
    const target = args[file.pathArg];
    if (typeof target !== 'string' || target === '') {
      return { actions: [], error: `${name} was called without a ${file.pathArg} argument, so its target cannot be checked` };
    }
    actions.push(createAction({ verb: file.verb, resourceType: 'filesystem', resourceValue: resolveTarget(target, cwd), context }));
  } else if (name === 'run_command') {
    const cmd = runCommandToActions(args, opts);
    if (cmd.error) return { actions: [], error: cmd.error };
    actions.push(...cmd.actions);
  } else if (!NO_RESOURCE_TOOLS.has(name)) {
    actions.push(createAction({ verb: 'invoke', resourceType: 'agent-tool', resourceValue: name, context }));
  }

  const seen = new Set();
  for (const value of collectStrings(args)) {
    for (const match of findSecretMatches(value)) {
      if (seen.has(match.name)) continue;
      seen.add(match.name);
      actions.push(createAction({ verb: 'transmit', resourceType: 'secret', resourceValue: match.name, context }));
    }
  }

  return { actions };
}
