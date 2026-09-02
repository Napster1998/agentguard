let counter = 0;

/** Resets the detection id counter — call between correlation runs/tests
 * that need deterministic ids. */
export function resetDetectionCounter() {
  counter = 0;
}

function nextId() {
  counter += 1;
  return `DETECT-${String(counter).padStart(3, '0')}`;
}

/**
 * A Detection is a correlation-engine finding: NOT proof of compromise, a
 * behavioral pattern match over a session's already-evaluated events. See
 * README "Event correlation" — this is deliberately a simple, deterministic
 * sequence check, not statistical/ML detection.
 *
 * @typedef {Object} Detection
 * @property {string} id
 * @property {string} title
 * @property {'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'} severity
 * @property {string} sessionId
 * @property {string[]} observedEventIds - the SecurityEvent ids that make up the pattern
 * @property {string} description
 * @property {string} recommendation
 */

/** @returns {Detection} */
export function createDetection({ title, severity, sessionId, observedEventIds, description, recommendation }) {
  return {
    id: nextId(),
    title,
    severity,
    sessionId,
    observedEventIds,
    description,
    recommendation,
  };
}
