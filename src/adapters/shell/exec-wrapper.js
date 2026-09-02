import { spawn } from 'node:child_process';
import crypto from 'node:crypto';

import { PolicyEngine } from '../../core/policy-engine.js';
import { AuditLogger } from '../../core/audit-logger.js';
import { combineDecisions, VERDICT } from '../../core/decision.js';
import { RISK } from '../../core/risk.js';
import { createAction } from '../../core/action.js';
import { createSecurityEvent } from '../../core/security-event.js';
import { looksLikePath, findSecretMatches, isInterpreterEvalAttempt } from '../../core/resource-heuristics.js';

const NO_ACTION_DECISION = { verdict: VERDICT.ALLOW, reason: 'No resources required policy evaluation.', risk: RISK.NONE, rule: null };

/**
 * Translates a real, already-split argv into Actions. Unlike the MCP
 * adapter — which has to guess resource shapes out of a joined command
 * string or a JSON blob with unknown key names — this gets real argv: the
 * binary is unambiguous, and each argument is evaluated on its own merits.
 */
function execArgsToActions(command, args, context) {
  const baseContext = { ...context, toolName: command, method: 'shell.exec' };
  const actions = [createAction({ verb: 'execute', resourceType: 'shell', resourceValue: command, context: baseContext })];

  if (isInterpreterEvalAttempt(command, args)) {
    actions.push(
      createAction({
        verb: 'execute',
        resourceType: 'interpreter-eval',
        resourceValue: `${command} ${args.join(' ')}`,
        context: baseContext,
      })
    );
  }

  for (const arg of args) {
    if (looksLikePath(arg)) {
      actions.push(createAction({ verb: 'read', resourceType: 'filesystem', resourceValue: arg, context: baseContext }));
    }
    for (const match of findSecretMatches(arg)) {
      actions.push(createAction({ verb: 'transmit', resourceType: 'secret', resourceValue: match.name, context: baseContext }));
    }
  }

  return actions;
}

/**
 * Evaluates `command args...` against policy BEFORE ever spawning it. On
 * BLOCK, the child process is never created — this is real prevention for
 * anything actually routed through this wrapper, not just after-the-fact
 * observation.
 *
 * IMPORTANT — enforcement boundary, not an EDR: this only protects commands
 * an agent/harness is actually configured to run through
 * `agentguard exec`, exactly like the MCP gateway only protects MCP traffic
 * actually routed through it. A command run directly, bypassing this
 * wrapper, is invisible to AgentGuard. See README "agentguard exec".
 *
 * @returns {Promise<{executed: boolean, exitCode: number, decision: object, event: object}>}
 */
export async function runExec({
  policy,
  command,
  args,
  cwd = process.cwd(),
  logFile,
  sessionId = crypto.randomUUID(),
  agentId,
}) {
  const engine = new PolicyEngine(policy);
  const logger = new AuditLogger({ logFile });

  const context = { source: 'shell-exec', sessionId, serverName: null };
  const actions = execArgsToActions(command, args, context);
  const subDecisions = actions.map((action) => ({ action, decision: engine.evaluate(action) }));
  const final = combineDecisions(
    subDecisions.map((s) => s.decision),
    NO_ACTION_DECISION
  );

  const event = createSecurityEvent({
    sessionId,
    agentId,
    source: 'shell-exec',
    actionType: 'SHELL_EXEC',
    toolName: command,
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
    metadata: { cwd, args },
  });
  logger.log(event);

  if (final.verdict === VERDICT.BLOCK) {
    logger.close();
    return { executed: false, exitCode: 1, decision: final, event };
  }

  const exitCode = await new Promise((resolve) => {
    const child = spawn(command, args, { cwd, stdio: 'inherit' });
    child.on('exit', (code) => resolve(code ?? 0));
    child.on('error', () => resolve(1));
  });

  logger.close();
  return { executed: true, exitCode, decision: final, event };
}
