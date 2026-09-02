let counters = Object.create(null);

/** Resets the per-category id counters — call between scans/tests that need
 * deterministic ids (a single process run otherwise keeps incrementing). */
export function resetFindingCounters() {
  counters = Object.create(null);
}

function nextId(category) {
  counters[category] = (counters[category] || 0) + 1;
  return `${category}-${String(counters[category]).padStart(3, '0')}`;
}

/**
 * @typedef {Object} SecurityFinding
 * @property {string} id            - e.g. "NET-001", generated per category
 * @property {string} title
 * @property {'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'} severity
 * @property {string} category      - e.g. 'agent', 'mcp', 'network', 'filesystem'
 * @property {string} description
 * @property {string} evidence      - MUST NOT contain secret values, only
 *                                     paths/ports/names
 * @property {string} recommendation
 */

/** @returns {SecurityFinding} */
export function createFinding({ category, title, severity, description, evidence, recommendation }) {
  return {
    id: nextId(category.toUpperCase()),
    title,
    severity,
    category,
    description,
    evidence,
    recommendation,
  };
}
