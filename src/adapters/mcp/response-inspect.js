import { findSecretMatches, findSuspiciousInstructionMatch } from '../../core/resource-heuristics.js';

/** Collects every string value, and separately the strings found under the
 * MCP content-block convention key `text` (as in `{type:'text', text:'...'}`)
 * in traversal order — the latter is used for a targeted concatenation
 * check below, since concatenating EVERY string (including "type"-style
 * discriminator fields sitting between real fragments) is too noisy to
 * reconstruct anything. */
function collectStrings(node, out = [], textOut = [], keyName = null) {
  if (node == null) return { all: out, text: textOut };
  if (typeof node === 'string') {
    out.push(node);
    if (keyName === 'text') textOut.push(node);
  } else if (Array.isArray(node)) {
    for (const v of node) collectStrings(v, out, textOut, keyName);
  } else if (typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) collectStrings(v, out, textOut, k);
  }
  return { all: out, text: textOut };
}

/**
 * Deterministic, pattern-based inspection of an MCP tool-call *response*.
 * This is a detection signal, not proof of compromise — see README "MCP
 * response inspection". Checks every collected string against the same
 * secret patterns used on the request side, plus a narrow, high-false-
 * negative instruction-injection pattern list.
 *
 * Also checks the un-separated concatenation of every string found under
 * the conventional `text` key (as in `{type:'text', text:'...'}` content
 * blocks) — a cheap, targeted defense against a secret/phrase deliberately
 * chunked across adjacent content blocks with no separator between
 * fragments. Trivially defeated by inserting unrelated text between the
 * pieces, or by a response shape that doesn't use the `text` key — see
 * SECURITY-ASSESSMENT.md F5. This is a bounded mitigation for the naive-
 * chunking case, not a general fix.
 *
 * @returns {Array<{type: 'secret-pattern'|'suspicious-instruction', detail: string}>}
 */
export function inspectResponse(result) {
  const { all, text } = collectStrings(result);
  const seen = new Map();

  const check = (s) => {
    for (const match of findSecretMatches(s)) {
      seen.set(`secret-pattern:${match.name}`, { type: 'secret-pattern', detail: match.name });
    }
    const suspicious = findSuspiciousInstructionMatch(s);
    if (suspicious) {
      seen.set(`suspicious-instruction:${suspicious.source}`, { type: 'suspicious-instruction', detail: suspicious.source });
    }
  };

  for (const s of all) check(s);
  if (text.length > 1) check(text.join(''));

  return [...seen.values()];
}
