import { createDetection } from './detection.js';

/**
 * Deterministic, explainable sequence rules over one session's
 * SecurityEvents. Each rule is a simple "does pattern A appear before
 * pattern B (before C)" scan — no scoring model, no ML, nothing
 * probabilistic. A Detection describes an observed BEHAVIORAL PATTERN, not
 * a conclusion about intent or compromise; see README "Event correlation"
 * and "Threat model".
 *
 * Deliberately scoped: correlation only looks within ONE session's events
 * (sessionId doesn't persist across gateway/exec-wrapper runs today — see
 * the "Identity" limitation), and each rule reports at most one Detection
 * per session even if the pattern recurs, to keep output readable. Rules
 * are not mutually exclusive — overlapping evidence can trigger more than
 * one rule, and that's shown, not deduplicated away.
 */

const SENSITIVE_RISK = new Set(['HIGH', 'CRITICAL']);

function isSensitiveRead(e) {
  return e.actionType === 'FILE_READ' && SENSITIVE_RISK.has(e.risk);
}
function isCredentialRead(e) {
  return e.actionType === 'FILE_READ' && e.risk === 'CRITICAL';
}
function isShellExec(e) {
  return e.actionType === 'SHELL_EXEC';
}
function isNetworkRequest(e) {
  return e.actionType === 'NETWORK_REQUEST';
}
function isUntrustedServerInvocation(e) {
  return e.rule === 'mcp.allowed_servers' && e.decision === 'WARN';
}

function firstIndexAfter(events, startIndex, predicate) {
  for (let i = startIndex + 1; i < events.length; i++) {
    if (predicate(events[i])) return i;
  }
  return -1;
}

function detectEscalationPattern(events, sessionId) {
  for (let i = 0; i < events.length; i++) {
    if (!isUntrustedServerInvocation(events[i])) continue;
    const j = firstIndexAfter(events, i, isSensitiveRead);
    if (j === -1) continue;
    const k = firstIndexAfter(events, j, isNetworkRequest);
    if (k === -1) continue;
    return [
      createDetection({
        title: 'Potential agent compromise pattern detected',
        severity: 'CRITICAL',
        sessionId,
        observedEventIds: [events[i].id, events[j].id, events[k].id],
        description: [
          'Observed sequence:',
          `1. Unknown MCP server invoked (${events[i].serverName})`,
          `2. Sensitive file targeted (${events[j].resource})`,
          `3. External destination requested (${events[k].destination || events[k].resource})`,
        ].join('\n'),
        recommendation:
          'This is a behavioral pattern match, not proof of compromise or malicious intent — investigate this session\'s actual events before concluding anything.',
      }),
    ];
  }
  return [];
}

function detectCredentialAccessThenShell(events, sessionId) {
  for (let i = 0; i < events.length; i++) {
    if (!isCredentialRead(events[i])) continue;
    const j = firstIndexAfter(events, i, isShellExec);
    if (j === -1) continue;
    return [
      createDetection({
        title: 'Credential access chain detected',
        severity: 'CRITICAL',
        sessionId,
        observedEventIds: [events[i].id, events[j].id],
        description: `A credential-level file read (${events[i].resource}) was followed by shell execution (${events[j].toolName}) in the same session.`,
        recommendation:
          'Treat this session as high-priority for review; a credential read followed by command execution is a classic exfiltration/misuse pattern.',
      }),
    ];
  }
  return [];
}

function detectSensitiveReadThenNetwork(events, sessionId) {
  for (let i = 0; i < events.length; i++) {
    if (!isSensitiveRead(events[i])) continue;
    const j = firstIndexAfter(events, i, isNetworkRequest);
    if (j === -1) continue;
    return [
      createDetection({
        title: 'Potential sensitive-data exposure pattern',
        severity: 'HIGH',
        sessionId,
        observedEventIds: [events[i].id, events[j].id],
        description: `A sensitive file read (${events[i].resource}) was followed by a network request (${events[j].destination || events[j].resource}) in the same session.`,
        recommendation: 'Review whether this agent session needed both sensitive-file access and external network access.',
      }),
    ];
  }
  return [];
}

function detectUntrustedServerThenSensitive(events, sessionId) {
  for (let i = 0; i < events.length; i++) {
    if (!isUntrustedServerInvocation(events[i])) continue;
    const j = firstIndexAfter(events, i, isSensitiveRead);
    if (j === -1) continue;
    return [
      createDetection({
        title: 'Untrusted MCP server led to sensitive-resource access',
        severity: 'HIGH',
        sessionId,
        observedEventIds: [events[i].id, events[j].id],
        description: `An untrusted MCP server ("${events[i].serverName}") was invoked, followed by a sensitive file read (${events[j].resource}) in the same session.`,
        recommendation: "Review this MCP server's trust level and why it preceded sensitive-resource access.",
      }),
    ];
  }
  return [];
}

/**
 * Runs every rule against one session's events (sorted by timestamp first —
 * callers may pass events in any order).
 * @returns {import('./detection.js').Detection[]}
 */
export function correlate(events, sessionId) {
  // Defensive: a caller-supplied event missing `timestamp` must not crash
  // this sort (see README/SECURITY-ASSESSMENT F7) — treat it as earliest.
  const sorted = [...events].sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));
  return [
    ...detectEscalationPattern(sorted, sessionId),
    ...detectCredentialAccessThenShell(sorted, sessionId),
    ...detectSensitiveReadThenNetwork(sorted, sessionId),
    ...detectUntrustedServerThenSensitive(sorted, sessionId),
  ];
}
