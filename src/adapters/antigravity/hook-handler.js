import { combineDecisions, VERDICT } from '../../core/decision.js';
import { RISK } from '../../core/risk.js';
import { createSecurityEvent } from '../../core/security-event.js';
import { parseHookPayload } from './payload.js';
import { toolCallToActions } from './tool-translator.js';

export const SOURCE = 'antigravity-hook';
const AGENT_ID = 'antigravity';

/**
 * The only answers AgentGuard ever gives Antigravity. `allow` defers to
 * Antigravity's own permission checks (the spike showed the hook runs BEFORE
 * them), so AgentGuard can only ever add restrictions. It never answers
 * `auto_approve`, never rewrites arguments (`overwrite`) and never grants
 * permissions (`permissionOverrides`).
 */
export const allow = () => ({ decision: 'allow' });
export const deny = (reason) => ({ decision: 'deny', reason });

/**
 * Handles one hook invocation: parse, translate, evaluate, record, answer.
 * Pure apart from `logger.log`. Never throws for bad INPUT (that becomes a
 * deny); the CLI wraps it in a catch-all for anything unexpected.
 *
 * @returns {{output: object, event: object|null}}
 */
export function handleHookInput(raw, { engine, logger, isMcpServerWrapped = () => false, parsePowerShell, platform, homedir, event: configuredEvent = null }) {
  const parsed = parseHookPayload(raw, { event: configuredEvent });
  if (!parsed.ok) {
    const event = recordFailure(logger, parsed.conversationId, `Hook input rejected: ${parsed.reason}.`, null, { payloadKeys: parsed.keys });
    return { output: deny(`AgentGuard could not evaluate this call: ${parsed.reason}.`), event };
  }

  // Only PreToolUse decides anything. Other events (if registered) are acknowledged.
  if (parsed.event !== 'PreToolUse') return { output: {}, event: null };

  const { toolCall } = parsed;
  const context = { source: SOURCE, sessionId: parsed.conversationId, toolName: toolCall.name, serverName: null };
  const { actions, error, skip, mcp } = toolCallToActions(toolCall, {
    cwd: parsed.cwd,
    context,
    isMcpServerWrapped,
    shellPolicy: engine.policy?.shell,
    parsePowerShell,
    platform,
    homedir,
  });

  if (error) {
    const event = recordFailure(logger, parsed.conversationId, `${error}.`, toolCall.name);
    return { output: deny(`AgentGuard could not evaluate this call: ${error}.`), event };
  }
  // A call the AgentGuard gateway will check itself: allow here, record nothing
  // (the gateway records it), so one call never appears twice.
  if (skip) return { output: allow(), event: null };

  const subDecisions = actions.map((action) => ({ action, decision: engine.evaluate(action) }));
  const final = combineDecisions(
    subDecisions.map((s) => s.decision),
    { verdict: VERDICT.ALLOW, reason: 'No resources required policy evaluation.', risk: RISK.LOW, rule: null }
  );
  // Same choice as the gateway: the resource the call is really about (a file,
  // a host) rather than the server invocation or a secret match.
  const primary =
    actions.find((a) => a.resource.type !== 'secret' && a.resource.type !== 'mcp-server') ||
    actions.find((a) => a.resource.type !== 'secret') ||
    actions[0];
  const network = actions.find((a) => a.resource.type === 'network');
  const recorded = recordedSummary(toolCall);

  const event = createSecurityEvent({
    sessionId: parsed.conversationId,
    agentId: AGENT_ID,
    source: SOURCE,
    direction: 'request',
    // run_command IS a shell execution, whatever its first evaluated part is
    // (an unparseable piece, a file), so correlation must see it as one.
    actionType: recorded?.actionType ?? primary?.actionType ?? null,
    // For an MCP call, the MCP tool and server, as the gateway records them.
    toolName: mcp ? mcp.tool : toolCall.name,
    serverName: mcp ? mcp.server : null,
    resource: [recorded?.summary, ...actions.map((a) => `${a.resource.type}:${a.resource.value}`)].filter(Boolean).join(', ') || null,
    destination: network?.resource.value ?? null,
    decision: final.verdict,
    risk: final.risk,
    rule: final.rule,
    reason: final.reason,
    subDecisions: subDecisions.map((s) => ({
      resourceType: s.action.resource.type,
      value: s.action.resource.value,
      verdict: s.decision.verdict,
      rule: s.decision.rule,
    })),
    metadata: compact({
      stepIdx: parsed.stepIdx,
      modelName: parsed.modelName,
      cwd: parsed.cwd,
      toolCallId: toolCall.id,
      // The command as the agent wrote it, for review. Any secret in it is
      // redacted when the event is built (F14).
      commandLine: typeof toolCall.args.CommandLine === 'string' ? toolCall.args.CommandLine.slice(0, 500) : undefined,
      bypassSandbox: toolCall.args.BypassSandbox === true ? true : undefined,
      via: mcp ? 'call_mcp_tool' : undefined,
    }),
  });
  logger.log(event);

  const output = final.verdict === VERDICT.BLOCK ? deny(`Blocked by AgentGuard policy: ${final.reason}`) : allow();
  return { output, event };
}

/** Records a call AgentGuard could not evaluate (and is therefore denying). */
export function recordFailure(logger, conversationId, reason, toolName = null, metadata = null) {
  const event = createSecurityEvent({
    sessionId: conversationId || 'antigravity-unidentified',
    agentId: AGENT_ID,
    source: SOURCE,
    direction: 'request',
    toolName,
    decision: VERDICT.BLOCK,
    risk: RISK.HIGH,
    rule: 'malformed-hook-input',
    reason: `${reason} Denied rather than allowed unevaluated.`,
    metadata: metadata && Object.values(metadata).some((v) => v != null) ? metadata : null,
  });
  try {
    logger.log(event);
  } catch {
    /* the answer (deny) matters more than the record */
  }
  return event;
}

/**
 * For run_command: it is a shell execution whatever its first evaluated part
 * is, plus a short readable summary of the line for `agentguard events`
 * (secrets in it are redacted when the event is built, F14).
 */
function recordedSummary({ name, args }) {
  if (name === 'run_command' && typeof args.CommandLine === 'string') {
    const line = args.CommandLine.replace(/\s+/g, ' ').trim();
    return { actionType: 'SHELL_EXEC', summary: `command-line:${line.length > 120 ? `${line.slice(0, 120)}...` : line}` };
  }
  return null;
}

function compact(obj) {
  return Object.fromEntries(Object.entries(obj).filter(([, v]) => v !== undefined && v !== null));
}
