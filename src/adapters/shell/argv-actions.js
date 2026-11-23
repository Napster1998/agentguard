import { createAction } from '../../core/action.js';
import { looksLikePath, findSecretMatches, isInterpreterEvalAttempt } from '../../core/resource-heuristics.js';
import { parseCommandLine } from '../../core/command-line.js';

/**
 * Translates a real, already-split argv into Actions: the binary (shell), an
 * interpreter-eval attempt if any (F2), and for each argument a filesystem read
 * if it looks like a path plus a secret action per matched pattern. Shared by
 * `agentguard exec` (real argv) and by the MCP adapter for each command its
 * command-line parser splits out, so both judge argv identically.
 */
export function argvToActions(command, args, context) {
  const actions = [createAction({ verb: 'execute', resourceType: 'shell', resourceValue: command, context })];

  if (isInterpreterEvalAttempt(command, args)) {
    actions.push(
      createAction({
        verb: 'execute',
        resourceType: 'interpreter-eval',
        resourceValue: `${command} ${args.join(' ')}`,
        context,
      })
    );
  }

  for (const arg of args) {
    if (looksLikePath(arg)) {
      actions.push(createAction({ verb: 'read', resourceType: 'filesystem', resourceValue: arg, context }));
    }
    for (const match of findSecretMatches(arg)) {
      actions.push(createAction({ verb: 'transmit', resourceType: 'secret', resourceValue: match.name, context }));
    }
  }

  return actions;
}

/**
 * Translates a command LINE (one string) into Actions. The line is split by
 * the strict parser in core/command-line.js; every command it contains goes
 * through argvToActions, and each redirect target becomes a file write
 * (`>`, `>>`) or read (`<`). A line the parser refuses becomes ONE
 * `shell-syntax` action naming what was refused (shell.block_unparseable_commands
 * decides it), never a guess at what would run. See SECURITY-ASSESSMENT.md F16.
 */
export function commandLineToActions(line, context) {
  const parsed = parseCommandLine(line);
  if (!parsed.ok) {
    return [createAction({ verb: 'execute', resourceType: 'shell-syntax', resourceValue: parsed.reason, context })];
  }

  const actions = [];
  for (const { argv, redirects } of parsed.commands) {
    actions.push(...argvToActions(argv[0], argv.slice(1), context));
    for (const { op, target } of redirects) {
      actions.push(
        createAction({ verb: op === '<' ? 'read' : 'write', resourceType: 'filesystem', resourceValue: target, context })
      );
      for (const match of findSecretMatches(target)) {
        actions.push(createAction({ verb: 'transmit', resourceType: 'secret', resourceValue: match.name, context }));
      }
    }
  }
  return actions;
}
