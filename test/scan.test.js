import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/adapters/discovery/scan.js';
import { applyDefaults } from '../src/core/policy-engine.js';

test('runScan produces a well-formed SecurityPosture without crashing on the real host', async () => {
  const posture = await runScan({ policy: applyDefaults({}) });

  assert.ok(posture.generatedAt);
  assert.ok(Array.isArray(posture.discoveredAgents));
  assert.ok(Array.isArray(posture.discoveredMcpServers));
  assert.ok(Array.isArray(posture.exposedServices));
  assert.ok(Array.isArray(posture.sensitiveResources));
  assert.ok(Array.isArray(posture.findings));
  assert.ok(['LOW RISK', 'MODERATE RISK', 'ELEVATED RISK', 'HIGH RISK'].includes(posture.overallRisk));
  assert.ok(posture.score >= 0 && posture.score <= 100);

  // Every finding must be well-formed and never leak anything beyond
  // path/severity-shaped evidence (spot-checked structurally, not by content
  // since we don't control what's actually on the host running this test).
  for (const finding of posture.findings) {
    assert.ok(finding.id);
    assert.ok(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(finding.severity));
    assert.equal(typeof finding.evidence, 'string');
  }
});
