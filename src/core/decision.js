export const VERDICT = Object.freeze({
  ALLOW: 'ALLOW',
  WARN: 'WARN',
  BLOCK: 'BLOCK',
});

const SEVERITY = { ALLOW: 0, WARN: 1, BLOCK: 2 };

/** Returns whichever verdict is the more severe of the two. */
export function moreSevere(a, b) {
  return SEVERITY[a] >= SEVERITY[b] ? a : b;
}

/**
 * @param {{verdict: string, reason: string, risk: string, rule: string|null}} fields
 */
export function makeDecision({ verdict, reason, risk, rule }) {
  return { verdict, reason, risk, rule };
}

/** Reduces a list of decisions to the single most severe one (ties keep the first). */
export function combineDecisions(decisions, fallback) {
  if (decisions.length === 0) return fallback;
  return decisions.reduce((acc, d) =>
    SEVERITY[d.verdict] > SEVERITY[acc.verdict] ? d : acc
  );
}
