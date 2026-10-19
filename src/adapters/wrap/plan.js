import path from 'node:path';

/**
 * Pure planning logic for `agentguard wrap` / `unwrap` / `status`: no
 * filesystem or process access, so it is exhaustively unit-testable.
 *
 * A wrapped entry looks like:
 *   command: <node>
 *   args:    [<agentguard.js>, 'gateway', '--policy', P, '--log', L,
 *             '--server-name', NAME, '--', <original command>, ...<original args>]
 * Everything needed to undo it is in the entry itself (it is the tail after
 * `--`), so unwrap never depends on a separate state file surviving.
 */

const REMOTE_TRANSPORTS = new Set(['sse', 'http', 'streamable-http', 'streamablehttp', 'websocket', 'ws']);

/** The args that precede the original command in a wrapped entry. */
export function wrapperPrefix(name, ctx) {
  return [ctx.scriptPath, 'gateway', '--policy', ctx.policyPath, '--log', ctx.logPath, '--server-name', name, '--'];
}

/** Is this entry one of ours (any version/paths)? Structural, not by marker. */
export function isWrappedEntry(def) {
  return (
    !!def &&
    Array.isArray(def.args) &&
    /^agentguard\.js$/i.test(path.basename(String(def.args[0] ?? ''))) &&
    def.args[1] === 'gateway' &&
    def.args.includes('--') &&
    def.args.indexOf('--') < def.args.length - 1
  );
}

/**
 * @returns {{state:'unwrapped'|'wrapped'|'stale'|'remote'|'invalid', reason?:string}}
 *   stale = already ours, but its node/script/policy/log paths differ from
 *   what they should be now (moved repo, upgraded node, new policy path).
 */
export function classifyEntry(name, def, ctx) {
  if (!def || typeof def !== 'object' || Array.isArray(def)) return { state: 'invalid', reason: 'entry is not an object' };

  if (isWrappedEntry(def)) {
    const expected = wrapperPrefix(name, ctx);
    const sep = def.args.indexOf('--');
    const prefix = def.args.slice(0, sep + 1);
    const same = def.command === ctx.nodePath && prefix.length === expected.length && prefix.every((v, i) => v === expected[i]);
    return same ? { state: 'wrapped' } : { state: 'stale', reason: 'wrapper paths differ from this install' };
  }

  const transport = typeof def.transport === 'string' ? def.transport.toLowerCase() : null;
  if (def.url || (transport && REMOTE_TRANSPORTS.has(transport))) {
    return { state: 'remote', reason: 'remote (HTTP/SSE) servers are not supported yet, so this one stays unprotected' };
  }
  if (typeof def.command !== 'string' || def.command.trim() === '') {
    return { state: 'invalid', reason: 'no command to wrap' };
  }
  if (def.args !== undefined && !Array.isArray(def.args)) return { state: 'invalid', reason: 'args is not a list' };
  if ((def.args || []).some((a) => typeof a !== 'string')) return { state: 'invalid', reason: 'args contains non-string values' };
  return { state: 'unwrapped' };
}

/** Original command + args of an entry that is ours. */
export function originalOf(def) {
  const sep = def.args.indexOf('--');
  return { command: def.args[sep + 1], args: def.args.slice(sep + 2) };
}

/** A wrapped copy of `def`; every other key (env, cwd, ...) is preserved. */
export function buildWrappedEntry(name, def, ctx) {
  const orig = isWrappedEntry(def) ? originalOf(def) : { command: def.command, args: def.args || [] };
  return { ...def, command: ctx.nodePath, args: [...wrapperPrefix(name, ctx), orig.command, ...orig.args] };
}

/** The pre-wrap entry. An empty original args list is restored as "no args key". */
export function buildUnwrappedEntry(def) {
  const { command, args } = originalOf(def);
  const out = { ...def, command, args };
  if (args.length === 0) delete out.args;
  return out;
}

/**
 * Per-server plan for one parsed config.
 * mode 'wrap'   : unwrapped -> wrap, stale -> repair, others -> skip
 * mode 'unwrap' : wrapped/stale -> unwrap, others -> skip
 */
export function planServers(table, mode, ctx) {
  return Object.entries(table).map(([name, def]) => {
    const cls = classifyEntry(name, def, ctx);
    let action = 'skip';
    let after = null;
    if (mode === 'wrap' && cls.state === 'unwrapped') {
      action = 'wrap';
      after = buildWrappedEntry(name, def, ctx);
    } else if (mode === 'wrap' && cls.state === 'stale') {
      action = 'repair';
      after = buildWrappedEntry(name, def, ctx);
    } else if (mode === 'unwrap' && (cls.state === 'wrapped' || cls.state === 'stale')) {
      action = 'unwrap';
      after = buildUnwrappedEntry(def);
    }
    return { name, state: cls.state, reason: cls.reason, action, before: def, after };
  });
}
