import { findSecretMatches, findSuspiciousInstructionMatch } from '../../core/resource-heuristics.js';

function collectStrings(node, out = []) {
  if (node == null) return out;
  if (typeof node === 'string') {
    out.push(node);
  } else if (Array.isArray(node)) {
    for (const v of node) collectStrings(v, out);
  } else if (typeof node === 'object') {
    for (const v of Object.values(node)) collectStrings(v, out);
  }
  return out;
}

/**
 * Deterministic, pattern-based inspection of an MCP tool-call *response*.
 * This is a detection signal, not proof of compromise — see README "MCP
 * response inspection". Recursively collects every string in the response
 * result and checks each against the same secret patterns used on the
 * request side, plus a narrow, high-false-negative instruction-injection
 * pattern list.
 *
 * @returns {Array<{type: 'secret-pattern'|'suspicious-instruction', detail: string}>}
 */
export function inspectResponse(result) {
  const findings = [];
  for (const s of collectStrings(result)) {
    for (const match of findSecretMatches(s)) {
      findings.push({ type: 'secret-pattern', detail: match.name });
    }
    const suspicious = findSuspiciousInstructionMatch(s);
    if (suspicious) {
      findings.push({ type: 'suspicious-instruction', detail: suspicious.source });
    }
  }
  return findings;
}
