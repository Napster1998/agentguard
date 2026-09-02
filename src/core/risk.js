export const RISK = Object.freeze({
  NONE: 'NONE',
  LOW: 'LOW',
  MEDIUM: 'MEDIUM',
  HIGH: 'HIGH',
  CRITICAL: 'CRITICAL',
});

const ORDER = [RISK.NONE, RISK.LOW, RISK.MEDIUM, RISK.HIGH, RISK.CRITICAL];

export function maxRisk(a, b) {
  return ORDER.indexOf(a) >= ORDER.indexOf(b) ? a : b;
}
