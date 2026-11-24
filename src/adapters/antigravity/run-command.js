import os from 'node:os';
import path from 'node:path';

import { createAction } from '../../core/action.js';
import { URL_RE, extractHostname, looksLikePath, isInterpreterEvalAttempt } from '../../core/resource-heuristics.js';
import { normalizeBinary } from '../../core/policy-engine.js';
import { commandLineToActions } from '../shell/argv-actions.js';
import { parseCommandLine } from '../../core/command-line.js';
import { parsePowerShell as defaultParsePowerShell } from './powershell-parser.js';
import {
  ALIASES,
  ALIASES_OF,
  CODE_AS_TEXT,
  FILE_CMDLETS,
  WRITERS,
  NON_PATH_PARAMS,
  COMPUTED_ARGS_OK,
  CHANGES_DIRECTORY,
  NATIVE_RECURSIVE,
} from './powershell-commands.js';

/**
 * Antigravity's run_command{CommandLine, BypassSandbox?} -> Actions.
 *
 * On Windows Antigravity runs the line in PowerShell (Phase 6 spike), so the
 * line is read by PowerShell's own parser (powershell-parser.js), never by a
 * guess. Every command it finds, including ones nested in script blocks and
 * subexpressions, is checked; one sentence per rule:
 *  1. Each command is a SHELL_EXEC on its name; a built-in alias counts as the
 *     command it stands for (and a policy entry for any of its names matches).
 *  2. Each literal argument is checked: a URL as a network destination; for a
 *     file cmdlet every non-parameter word, otherwise any path-shaped word, as
 *     a file (resolved against the workspace, or a literal `cd` target).
 *  3. Not evaluable, so UNPARSEABLE (shell.block_unparseable_commands): a
 *     syntax error, a command whose name is computed, a .NET method call
 *     (it reaches files and network with no command at all),
 *     Invoke-Expression / Add-Type (code given as text), or a computed argument
 *     to anything but a pipeline/formatting cmdlet.
 *  4. A file redirection target is a FILE_WRITE, whether it follows a command
 *     or an expression ('x' > file); ${C:\path} variable syntax (reads or
 *     writes a file with no command) is UNPARSEABLE.
 *  5. An interpreter with an inline-code flag (incl. powershell -enc / -co) is
 *     an interpreter-eval attempt (F2).
 *  6. A recursive search rooted at the home folder or above is flagged
 *     (filesystem.recursive_search_from_home).
 *  7. BypassSandbox:true is flagged (shell.unsandboxed).
 *
 * On other systems the strict cross-shell parser (F16) is used, plus rule 6
 * for grep -r / rg / find / ls -R (posixRecursiveSearches). Verified on Linux
 * (Phase 6.5): Antigravity runs commands there in a non-interactive bash, and
 * the F16 grammar is a safe subset of it. macOS is untested.
 *
 * Residuals, stated: what an allowed program does on its own (npm scripts, git
 * config) is not judged (F2 class); file targets that arrive through the
 * pipeline (`Get-ChildItem | Move-Item -Destination x`) are not known.
 */
export function runCommandToActions(args, opts) {
  const { context } = opts;
  const line = args.CommandLine;
  if (typeof line !== 'string' || line.trim() === '') {
    return { actions: [], error: 'run_command was called without a CommandLine, so the command cannot be checked' };
  }

  const actions = [];
  if (args.BypassSandbox === true) {
    actions.push(createAction({ verb: 'execute', resourceType: 'shell-unsandboxed', resourceValue: 'BypassSandbox', context }));
  }
  if ((opts.platform ?? process.platform) !== 'win32') {
    actions.push(...commandLineToActions(line, context), ...posixRecursiveSearches(line, opts));
    return { actions };
  }
  actions.push(...powerShellLineToActions(line, opts));
  return { actions };
}

function unparseable(reason, context) {
  return createAction({ verb: 'execute', resourceType: 'shell-syntax', resourceValue: reason, context });
}

const clip = (s, n = 60) => (s.length > n ? `${s.slice(0, n)}...` : s);

function powerShellLineToActions(line, { cwd, context, shellPolicy, parsePowerShell = defaultParsePowerShell, homedir = os.homedir() }) {
  const parsed = parsePowerShell(line);
  if (!parsed.ok) return [unparseable(parsed.reason, context)];
  const { errors, commands, methodCalls, otherRedirections = [], driveVariables = [] } = parsed.ast;
  if (errors.length) return [unparseable(`a PowerShell syntax error ("${clip(errors[0])}")`, context)];

  const actions = [];
  for (const m of methodCalls) actions.push(unparseable(`a .NET method call (${clip(m)}), which can reach files and the network without any command`, context));
  for (const v of driveVariables) actions.push(unparseable(`a file accessed through variable syntax (${clip(v)}), with no command`, context));
  // A redirection after an expression ('x' > file), not attached to any command.
  for (const r of otherRedirections) {
    if (r.target?.k === 'lit') actions.push(createAction({ verb: 'write', resourceType: 'filesystem', resourceValue: resolveIn(cwd, r.target.v), context }));
    else actions.push(unparseable(`a redirection to a computed target (${clip(r.target?.text || '?')})`, context));
  }

  let dir = cwd;
  for (const cmd of commands) {
    if (!cmd.name) {
      actions.push(unparseable(`a command whose name is only known at run time (${clip(cmd.firstText || '?')})`, context));
      continue;
    }
    const canonical = ALIASES[cmd.name.toLowerCase()] || cmd.name;
    const key = canonical.toLowerCase();
    if (CODE_AS_TEXT.has(key)) {
      actions.push(unparseable(`${canonical}, which runs code given to it as text`, context));
      continue;
    }

    actions.push(createAction({ verb: 'execute', resourceType: 'shell', resourceValue: policyName(cmd.name, canonical, shellPolicy), context }));

    // Arguments as the command will see them, for the interpreter check.
    const argv = [];
    const literals = []; // { value, param }
    let param = null;
    const takeLiteral = (value) => {
      argv.push(value);
      literals.push({ value, param });
      param = null;
    };
    for (const el of cmd.elements) {
      if (el.k === 'param') {
        argv.push(`-${el.n}`);
        param = el.n.toLowerCase();
        if (el.arg) {
          if (el.arg.k === 'lit') takeLiteral(el.arg.v);
          else if (!computedOk(key, el.arg)) actions.push(unparseable(`a computed argument (${clip(el.arg.text || '?')}) to ${canonical}`, context));
          param = null;
        }
      } else if (el.k === 'lit') {
        takeLiteral(el.v);
      } else if (el.k === 'arr' && el.items.every((i) => i && i.k === 'lit')) {
        el.items.forEach((i) => takeLiteral(i.v));
      } else if (!computedOk(key, el)) {
        actions.push(unparseable(`a computed argument (${clip(el.text || el.t || '?')}) to ${canonical}`, context));
        param = null;
      }
    }

    if (isInterpreterEvalAttempt(cmd.name, argv) || isInterpreterEvalAttempt(canonical, argv)) {
      actions.push(createAction({ verb: 'execute', resourceType: 'interpreter-eval', resourceValue: `${cmd.name} ${argv.join(' ')}`, context }));
    }

    const isFileCmdlet = FILE_CMDLETS.has(key);
    const verb = WRITERS.has(key) ? 'write' : 'read';
    const paths = [];
    for (const { value, param: p } of literals) {
      if (URL_RE.test(value)) {
        const host = extractHostname(value);
        if (host) actions.push(createAction({ verb: 'network', resourceType: 'network', resourceValue: host, context }));
      } else if ((isFileCmdlet && !NON_PATH_PARAMS.has(p)) || looksLikePath(value)) {
        const target = resolveIn(dir, value);
        paths.push(target);
        actions.push(createAction({ verb: isFileCmdlet ? verb : 'read', resourceType: 'filesystem', resourceValue: target, context }));
      }
    }

    // 6. Recursive search from the home folder or above.
    const recursive =
      (key === 'get-childitem' && argv.some((a) => /^-r(e(c(u(r(s(e)?)?)?)?)?)?$/i.test(a))) ||
      (NATIVE_RECURSIVE[normalizeBinary(cmd.name)]?.(argv) ?? false);
    if (recursive) {
      const root = paths[0] || dir;
      if (root && isHomeOrAbove(root, homedir)) {
        actions.push(createAction({ verb: 'read', resourceType: 'filesystem-recursive', resourceValue: root, context }));
      }
    }

    for (const r of cmd.redirections) {
      if (r.k !== 'file') continue;
      if (r.target?.k === 'lit') {
        actions.push(createAction({ verb: 'write', resourceType: 'filesystem', resourceValue: resolveIn(dir, r.target.v), context }));
      } else {
        actions.push(unparseable(`a redirection to a computed target (${clip(r.target?.text || '?')})`, context));
      }
    }

    if (CHANGES_DIRECTORY.has(key) && paths[0]) dir = paths[0];
  }
  return actions;
}

/**
 * Rule 6 for bash (Linux/macOS): grep -r/-R, rg, find and ls -R rooted at the
 * home folder or above. The search root is the first operand that is not the
 * search pattern (grep/rg take the pattern first unless -e/-f gives it), or
 * the workspace when none is given. A line the strict parser refuses is
 * already blocked, so only parsed lines are looked at.
 */
const POSIX_RECURSIVE = {
  grep: { recursive: (flags) => flags.some((f) => f === '--recursive' || /^-[a-zA-Z]*[rR]/.test(f)), patternFirst: true },
  egrep: { recursive: (flags) => flags.some((f) => f === '--recursive' || /^-[a-zA-Z]*[rR]/.test(f)), patternFirst: true },
  rg: { recursive: () => true, patternFirst: true },
  find: { recursive: () => true, patternFirst: false, findStyle: true },
  ls: { recursive: (flags) => flags.some((f) => f === '--recursive' || /^-[a-zA-Z]*R/.test(f)), patternFirst: false },
};

function posixRecursiveSearches(line, { cwd, context, homedir = os.homedir() }) {
  const parsed = parseCommandLine(line);
  if (!parsed.ok) return [];
  const actions = [];
  for (const { argv } of parsed.commands) {
    const spec = POSIX_RECURSIVE[normalizeBinary(argv[0])];
    if (!spec) continue;
    const args = argv.slice(1);
    const flags = args.filter((a) => a.startsWith('-'));
    if (!spec.recursive(flags)) continue;
    // find: operands come before the first expression (-name, (, !, ...).
    const { operands, patternGiven } = spec.patternFirst
      ? grepOperands(args)
      : { operands: spec.findStyle ? takeWhileOperand(args) : args.filter((a) => !a.startsWith('-')), patternGiven: true };
    const roots = patternGiven ? operands : operands.slice(1);
    const root = roots.length ? resolveIn(cwd, roots[0]) : cwd;
    if (root && isHomeOrAbove(root, homedir)) {
      actions.push(createAction({ verb: 'read', resourceType: 'filesystem-recursive', resourceValue: root, context }));
    }
  }
  return actions;
}

/** grep/rg operands, skipping the value of -e/-f (the pattern, when given that way). */
function grepOperands(args) {
  const operands = [];
  let patternGiven = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--regexp=') || a.startsWith('--file=')) patternGiven = true;
    else if (a === '--regexp' || a === '--file' || /^-[a-zA-Z]*[ef]$/.test(a)) {
      patternGiven = true;
      i++; // its value
    } else if (!a.startsWith('-')) operands.push(a);
  }
  return { operands, patternGiven };
}

function takeWhileOperand(args) {
  const out = [];
  for (const a of args) {
    if (a.startsWith('-') || a === '(' || a === '!') break;
    out.push(a);
  }
  return out;
}

/** Script blocks are fine anywhere (the commands inside are checked on their own); other computed values only where they cannot pick a target. */
function computedOk(cmdKey, el) {
  return el.t === 'ScriptBlockExpressionAst' || COMPUTED_ARGS_OK.has(cmdKey);
}

/**
 * The name the policy sees for a command. PowerShell has several names for one
 * command (rm, del, Remove-Item...), and a policy may list any of them: a
 * deny entry for any name wins, then an allow entry for any name, else the
 * real command name.
 */
function policyName(typed, canonical, shellPolicy = { deny: [], allowed: [] }) {
  const names = [...new Set([typed, canonical, ...(ALIASES_OF[canonical.toLowerCase()] || [])])];
  const deny = new Set((shellPolicy.deny || []).map(normalizeBinary));
  const allowed = new Set((shellPolicy.allowed || []).map(normalizeBinary));
  return names.find((n) => deny.has(normalizeBinary(n))) || names.find((n) => allowed.has(normalizeBinary(n))) || canonical;
}

const WINDOWS_PATH_RE = /^[A-Za-z]:[\\/]|^\\\\/;

function resolveIn(dir, p) {
  if (p.startsWith('~') || path.posix.isAbsolute(p) || path.win32.isAbsolute(p) || !dir) return p;
  return (WINDOWS_PATH_RE.test(dir) ? path.win32 : path.posix).resolve(dir, p);
}

function isHomeOrAbove(root, homedir) {
  const norm = (p) => p.replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase();
  const r = root.startsWith('~') ? norm(homedir) + norm(root.slice(1)) : norm(root);
  const home = norm(homedir);
  return r === home || r === '' || /^[a-z]:$/.test(r) || home.startsWith(`${r}/`);
}
