import { spawn } from 'node:child_process';
import readline from 'node:readline';
import crypto from 'node:crypto';

import { PolicyEngine } from '../../core/policy-engine.js';
import { AuditLogger } from '../../core/audit-logger.js';
import { combineDecisions, VERDICT } from '../../core/decision.js';
import { RISK } from '../../core/risk.js';
import { assessRisk } from '../../core/risk-engine.js';
import { createSecurityEvent } from '../../core/security-event.js';
import { mcpRequestToActions } from './translate.js';
import { inspectResponse } from './response-inspect.js';
import { resolveSpawnTarget } from '../host/spawn-target.js';

const NO_ACTION_DECISION = { verdict: VERDICT.ALLOW, reason: 'No resources required policy evaluation.', risk: RISK.NONE, rule: null };

/**
 * Starts the gateway: agent <-stdio-> this process <-stdio-> real MCP server.
 *
 * MCP's stdio transport is newline-delimited JSON-RPC 2.0 — one message per
 * line. Every `tools/call` from the agent is translated into Actions,
 * evaluated, and either forwarded (ALLOW/WARN) or answered locally with a
 * synthesized JSON-RPC error (BLOCK) so the agent fails cleanly instead of
 * hanging. All other request methods pass straight through untouched.
 *
 * Responses to a forwarded `tools/call` are inspected on the way back (see
 * response-inspect.js) before being relayed to the agent.
 */
export function startProxy({ policy, serverCommand, serverArgs, logFile, serverName, stdin = process.stdin, stdout = process.stdout }) {
  const engine = new PolicyEngine(policy);
  const logger = new AuditLogger({ logFile });
  const sessionId = crypto.randomUUID();
  // The strongest identity signal MCP actually gives us: the `initialize`
  // handshake's clientInfo.name. Falls back to sessionId when a client
  // never sends it — see README "Identity" limitation.
  let agentId = sessionId;
  // Requests we forwarded and are still waiting on a response for, so the
  // response handler knows which tool/server it belongs to.
  const pendingRequests = new Map();

  // May throw SpawnRefusal (Windows .cmd shim with cmd.exe-unsafe characters);
  // the CLI turns that into a clean one-line error.
  const target = resolveSpawnTarget(serverCommand, serverArgs);
  const child = spawn(target.command, target.args, { stdio: ['pipe', 'pipe', 'inherit'] });

  const childOut = readline.createInterface({ input: child.stdout });
  childOut.on('line', (line) => {
    if (!line.trim()) return;
    handleChildLine(line);
  });

  const agentIn = readline.createInterface({ input: stdin });
  agentIn.on('line', (line) => {
    if (!line.trim()) return;

    let message;
    try {
      message = JSON.parse(line);
    } catch (err) {
      // SECURITY: a line we cannot parse is a line we cannot evaluate, and
      // a security gateway must never let "cannot evaluate" silently mean
      // "forward anyway" (that is an unconditional ALLOW with zero policy
      // applied). Fail CLOSED: drop it rather than relay it to the real
      // server. The agent's request will time out instead of succeeding
      // unevaluated — the correct trade-off for a security boundary.
      logger.log(
        createSecurityEvent({
          sessionId,
          agentId,
          source: 'mcp',
          direction: 'request',
          decision: VERDICT.BLOCK,
          risk: RISK.HIGH,
          rule: 'malformed-json',
          reason: `Line could not be parsed as JSON-RPC and was dropped rather than forwarded unevaluated: ${err.message}`,
        })
      );
      return;
    }

    handleMessage(message);
  });

  function handleMessage(message) {
    if (message.method === 'initialize') {
      const clientInfo = message.params?.clientInfo;
      if (clientInfo?.name) agentId = clientInfo.name;
      child.stdin.write(JSON.stringify(message) + '\n');
      return;
    }

    if (message.method !== 'tools/call') {
      child.stdin.write(JSON.stringify(message) + '\n');
      return;
    }

    const context = { source: 'mcp', sessionId, serverName, timestamp: new Date().toISOString() };
    const actions = mcpRequestToActions(message, context);
    const subDecisions = actions.map((action) => ({ action, decision: engine.evaluate(action) }));
    const final = combineDecisions(
      subDecisions.map((s) => s.decision),
      NO_ACTION_DECISION
    );

    const primaryAction = actions.find((a) => a.resource.type !== 'mcp-server') || actions[0];
    const networkAction = actions.find((a) => a.resource.type === 'network');

    const event = createSecurityEvent({
      sessionId,
      agentId,
      source: 'mcp',
      direction: 'request',
      actionType: primaryAction?.actionType ?? null,
      toolName: message.params?.name ?? null,
      serverName,
      resource: actions.map((a) => `${a.resource.type}:${a.resource.value}`).join(', ') || null,
      destination: networkAction?.resource.value ?? null,
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
      timestamp: context.timestamp,
    });
    logger.log(event);

    if (final.verdict === VERDICT.BLOCK) {
      const response = {
        jsonrpc: '2.0',
        id: message.id,
        error: {
          code: -32001,
          message: `Blocked by AgentGuard policy: ${final.reason}`,
          data: { risk: final.risk, rule: final.rule, eventId: event.id },
        },
      };
      stdout.write(JSON.stringify(response) + '\n');
      return;
    }

    // ALLOW and WARN both forward (WARN is fail-open, for visibility).
    // Remember this request so the matching response can be inspected.
    if (message.id !== undefined) {
      pendingRequests.set(message.id, { toolName: message.params?.name ?? null });
    }
    child.stdin.write(JSON.stringify(message) + '\n');
  }

  function handleChildLine(line) {
    let message;
    try {
      message = JSON.parse(line);
    } catch (err) {
      // Same fail-closed reasoning as the request side: a response we
      // cannot parse is a response we cannot inspect, so it must not reach
      // the agent uninspected.
      logger.log(
        createSecurityEvent({
          sessionId,
          agentId,
          source: 'mcp',
          direction: 'response',
          decision: VERDICT.BLOCK,
          risk: RISK.MEDIUM,
          rule: 'malformed-json',
          reason: `Response line could not be parsed as JSON-RPC and was dropped rather than forwarded uninspected: ${err.message}`,
        })
      );
      return;
    }

    // Inspect any response carrying a `result`, tracked or not: a second
    // response reusing an already-consumed id, or an unsolicited response
    // with a fabricated id, must not skip inspection just because it isn't
    // (or is no longer) in pendingRequests — that would let a malicious/
    // compromised downstream server bypass response inspection entirely.
    const pending = message.id !== undefined ? pendingRequests.get(message.id) : undefined;
    if (pending) pendingRequests.delete(message.id);

    if (message.result === undefined) {
      stdout.write(line + '\n');
      return;
    }

    const findings = inspectResponse(message.result);
    if (findings.length === 0) {
      stdout.write(line + '\n');
      return;
    }

    const hasSecret = findings.some((f) => f.type === 'secret-pattern');
    const hasSuspicious = findings.some((f) => f.type === 'suspicious-instruction');

    let verdict = VERDICT.WARN;
    let risk = RISK.MEDIUM;
    let reason;
    let rule;

    if (hasSecret) {
      verdict = policy.mcp_response_inspection.block_on_secret_pattern ? VERDICT.BLOCK : VERDICT.WARN;
      risk = assessRisk({ sensitivity: RISK.CRITICAL, verdict, credentialInvolved: true });
      reason = `Response contains a known secret pattern (${findings
        .filter((f) => f.type === 'secret-pattern')
        .map((f) => f.detail)
        .join(', ')}).`;
      rule = 'mcp_response_inspection.block_on_secret_pattern';
    } else if (hasSuspicious) {
      verdict = policy.mcp_response_inspection.block_on_suspicious_instruction ? VERDICT.BLOCK : VERDICT.WARN;
      risk = assessRisk({ sensitivity: RISK.MEDIUM, verdict });
      reason = 'Response contains an instruction-injection-shaped pattern. This is a detection signal, not confirmed compromise.';
      rule = 'mcp_response_inspection.block_on_suspicious_instruction';
    }

    const event = createSecurityEvent({
      sessionId,
      agentId,
      source: 'mcp',
      direction: 'response',
      actionType: null,
      toolName: pending?.toolName ?? null,
      serverName,
      resource: null,
      decision: verdict,
      risk,
      rule,
      reason,
      subDecisions: findings,
    });
    logger.log(event);

    if (verdict === VERDICT.BLOCK) {
      const response = {
        jsonrpc: '2.0',
        id: message.id,
        error: {
          code: -32002,
          message: `Response blocked by AgentGuard policy: ${reason}`,
          data: { risk, rule, eventId: event.id },
        },
      };
      stdout.write(JSON.stringify(response) + '\n');
      return;
    }

    // WARN forwards the original response unchanged (fail-open, logged).
    stdout.write(line + '\n');
  }

  // The downstream server could not even be started (missing command, bad
  // permissions). Say so in one line instead of an unhandled-'error' stack
  // trace, and stop: a gateway with no server behind it can only hang.
  child.on('error', (err) => {
    process.stderr.write(`[AgentGuard] could not start the MCP server "${serverCommand}": ${err.code || err.message}\n`);
    logger.close();
    agentIn.close();
    process.exitCode = 1;
  });

  child.on('exit', (code) => {
    logger.close();
    process.exitCode = code ?? 0;
  });

  return { child, logger, sessionId };
}
