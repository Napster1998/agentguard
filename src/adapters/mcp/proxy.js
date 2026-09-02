import { spawn } from 'node:child_process';
import readline from 'node:readline';
import crypto from 'node:crypto';

import { PolicyEngine } from '../../core/policy-engine.js';
import { AuditLogger } from '../../core/audit-logger.js';
import { combineDecisions, VERDICT } from '../../core/decision.js';
import { RISK } from '../../core/risk.js';
import { createSecurityEvent } from '../../core/security-event.js';
import { mcpRequestToActions } from './translate.js';

const NO_ACTION_DECISION = { verdict: VERDICT.ALLOW, reason: 'No resources required policy evaluation.', risk: RISK.NONE, rule: null };

/**
 * Starts the gateway: agent <-stdio-> this process <-stdio-> real MCP server.
 *
 * MCP's stdio transport is newline-delimited JSON-RPC 2.0 — one message per
 * line. Every `tools/call` from the agent is translated into Actions,
 * evaluated, and either forwarded (ALLOW/WARN) or answered locally with a
 * synthesized JSON-RPC error (BLOCK) so the agent fails cleanly instead of
 * hanging. All other methods pass straight through.
 */
export function startProxy({ policy, serverCommand, serverArgs, logFile, serverName, stdin = process.stdin, stdout = process.stdout }) {
  const engine = new PolicyEngine(policy);
  const logger = new AuditLogger({ logFile });
  const sessionId = crypto.randomUUID();

  const child = spawn(serverCommand, serverArgs, { stdio: ['pipe', 'pipe', 'inherit'] });

  const childOut = readline.createInterface({ input: child.stdout });
  childOut.on('line', (line) => {
    if (line.trim()) stdout.write(line + '\n');
  });

  const agentIn = readline.createInterface({ input: stdin });
  agentIn.on('line', (line) => {
    if (!line.trim()) return;

    let message;
    try {
      message = JSON.parse(line);
    } catch {
      // Not valid JSON-RPC. Fail safe by forwarding rather than silently
      // dropping bytes, which could hang the agent on a malformed line.
      child.stdin.write(line + '\n');
      return;
    }

    handleMessage(message);
  });

  function handleMessage(message) {
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

    const event = createSecurityEvent({
      sessionId,
      source: 'mcp',
      actionType: primaryAction?.actionType ?? null,
      toolName: message.params?.name ?? null,
      serverName,
      resource: actions.map((a) => `${a.resource.type}:${a.resource.value}`).join(', ') || null,
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

    // ALLOW and WARN both forward in Phase 1 (WARN is fail-open, for visibility).
    child.stdin.write(JSON.stringify(message) + '\n');
  }

  child.on('exit', (code) => {
    logger.close();
    process.exitCode = code ?? 0;
  });

  return { child, logger, sessionId };
}
