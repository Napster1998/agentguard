import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createFinding, resetFindingCounters } from '../src/core/security-finding.js';
import { createPosture } from '../src/core/security-posture.js';

test('createFinding assigns sequential per-category ids', () => {
  resetFindingCounters();
  const a = createFinding({ category: 'net', title: 'a', severity: 'HIGH', description: 'd', evidence: 'e', recommendation: 'r' });
  const b = createFinding({ category: 'net', title: 'b', severity: 'LOW', description: 'd', evidence: 'e', recommendation: 'r' });
  const c = createFinding({ category: 'fs', title: 'c', severity: 'LOW', description: 'd', evidence: 'e', recommendation: 'r' });
  assert.equal(a.id, 'NET-001');
  assert.equal(b.id, 'NET-002');
  assert.equal(c.id, 'FS-001');
});

test('createPosture with no findings -> LOW RISK, score 100', () => {
  const posture = createPosture({});
  assert.equal(posture.overallRisk, 'LOW RISK');
  assert.equal(posture.score, 100);
  assert.deepEqual(posture.severityCounts, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 });
});

test('createPosture matches the brief\'s worked example: 1 CRITICAL, 2 HIGH, 2 MEDIUM, 1 LOW -> HIGH RISK', () => {
  resetFindingCounters();
  const findings = [
    createFinding({ category: 'fs', title: 'a', severity: 'CRITICAL', description: 'd', evidence: 'e', recommendation: 'r' }),
    createFinding({ category: 'fs', title: 'b', severity: 'HIGH', description: 'd', evidence: 'e', recommendation: 'r' }),
    createFinding({ category: 'fs', title: 'c', severity: 'HIGH', description: 'd', evidence: 'e', recommendation: 'r' }),
    createFinding({ category: 'fs', title: 'd', severity: 'MEDIUM', description: 'd', evidence: 'e', recommendation: 'r' }),
    createFinding({ category: 'fs', title: 'e', severity: 'MEDIUM', description: 'd', evidence: 'e', recommendation: 'r' }),
    createFinding({ category: 'fs', title: 'f', severity: 'LOW', description: 'd', evidence: 'e', recommendation: 'r' }),
  ];
  const posture = createPosture({ findings });
  assert.equal(posture.overallRisk, 'HIGH RISK');
  assert.deepEqual(posture.severityCounts, { CRITICAL: 1, HIGH: 2, MEDIUM: 2, LOW: 1 });
});

test('createPosture score is clamped to 0', () => {
  resetFindingCounters();
  const findings = Array.from({ length: 10 }, (_, i) =>
    createFinding({ category: 'fs', title: `f${i}`, severity: 'CRITICAL', description: 'd', evidence: 'e', recommendation: 'r' })
  );
  const posture = createPosture({ findings });
  assert.equal(posture.score, 0);
});

test('a single MEDIUM finding -> MODERATE RISK, not HIGH', () => {
  resetFindingCounters();
  const findings = [createFinding({ category: 'fs', title: 'a', severity: 'MEDIUM', description: 'd', evidence: 'e', recommendation: 'r' })];
  const posture = createPosture({ findings });
  assert.equal(posture.overallRisk, 'MODERATE RISK');
});
