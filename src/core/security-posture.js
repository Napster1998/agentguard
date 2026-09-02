const SEVERITY_DEDUCTION = { CRITICAL: 25, HIGH: 12, MEDIUM: 6, LOW: 2 };

/**
 * A deliberately simple, deterministic score: start at 100, subtract a
 * fixed amount per finding severity, clamp to [0, 100]. This is indicative,
 * not a calibrated risk score — do not read precision into the number that
 * isn't there. The severity counts (below) are the primary signal; the
 * score is a secondary at-a-glance summary.
 */
function computeScore(findings) {
  const deducted = findings.reduce((sum, f) => sum + (SEVERITY_DEDUCTION[f.severity] || 0), 0);
  return Math.max(0, Math.min(100, 100 - deducted));
}

function countBySeverity(findings) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  return counts;
}

/**
 * Overall label is deliberately coarse (four tiers) rather than a direct
 * restatement of the worst single finding — one CRITICAL finding among an
 * otherwise clean environment is "HIGH RISK", not a separate top label,
 * matching how the posture is meant to be read at a glance.
 */
function computeOverallRisk(counts) {
  if (counts.CRITICAL > 0 || counts.HIGH >= 2) return 'HIGH RISK';
  if (counts.HIGH > 0 || counts.MEDIUM >= 3) return 'ELEVATED RISK';
  if (counts.MEDIUM > 0) return 'MODERATE RISK';
  return 'LOW RISK';
}

/**
 * @typedef {Object} SecurityPosture
 * @property {string} generatedAt
 * @property {Array<object>} discoveredAgents
 * @property {Array<object>} discoveredMcpServers
 * @property {Array<object>} exposedServices
 * @property {Array<object>} sensitiveResources
 * @property {Array<import('./security-finding.js').SecurityFinding>} findings
 * @property {{CRITICAL:number,HIGH:number,MEDIUM:number,LOW:number}} severityCounts
 * @property {number} score
 * @property {string} overallRisk
 */

/** @returns {SecurityPosture} */
export function createPosture({
  discoveredAgents = [],
  discoveredMcpServers = [],
  exposedServices = [],
  sensitiveResources = [],
  findings = [],
}) {
  const severityCounts = countBySeverity(findings);
  return {
    generatedAt: new Date().toISOString(),
    discoveredAgents,
    discoveredMcpServers,
    exposedServices,
    sensitiveResources,
    findings,
    severityCounts,
    score: computeScore(findings),
    overallRisk: computeOverallRisk(severityCounts),
  };
}
