import { RISK, maxRisk } from './risk.js';
import { VERDICT } from './decision.js';

/**
 * Deterministic risk assessment from explainable factors — not an arbitrary
 * per-branch literal. PolicyEngine computes a resource `sensitivity` while
 * it evaluates a rule; this function turns that plus the verdict into the
 * risk level actually reported, by one consistent rule:
 *
 *  - a credential match always forces CRITICAL, regardless of anything else
 *  - BLOCK is never reported below HIGH (a denied action is inherently risky
 *    even if the specific resource's baseline sensitivity is lower)
 *  - WARN is never reported below MEDIUM
 *  - ALLOW reports the resource's own sensitivity (with a LOW floor — every
 *    observed action carries some baseline risk simply by being an action)
 *
 * See README "Risk model" for the worked examples this reproduces.
 */
export function assessRisk({ sensitivity, verdict, credentialInvolved = false }) {
  if (credentialInvolved) return RISK.CRITICAL;

  switch (verdict) {
    case VERDICT.BLOCK:
      return maxRisk(sensitivity, RISK.HIGH);
    case VERDICT.WARN:
      return maxRisk(sensitivity, RISK.MEDIUM);
    case VERDICT.ALLOW:
    default:
      return sensitivity === RISK.NONE ? RISK.LOW : sensitivity;
  }
}
