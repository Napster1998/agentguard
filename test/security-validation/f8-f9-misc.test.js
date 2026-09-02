// F8 (LOW, FIXED) and F9 (LOW, FIXED).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PolicyEngine, applyDefaults } from '../../src/core/policy-engine.js';
import { assessNetworkExposure } from '../../src/adapters/discovery/network-exposure.js';

// F8: PolicyEngine's fallback for an unrecognized resource type now WARNs
// instead of ALLOWing - fails safe, not open, per the project's own
// stated principle. Still not attacker-reachable today (only trusted
// adapter code produces resource types); this protects the NEXT adapter.
test('F8 FIXED: an unrecognized resource type now WARNs rather than silently ALLOWing', () => {
  const engine = new PolicyEngine(applyDefaults({}));
  const d = engine.evaluate({ verb: 'do-something', resource: { type: 'totally-new-resource-type', value: 'x' }, context: {} });
  assert.equal(d.verdict, 'WARN');
  assert.equal(d.risk, 'MEDIUM');
});

// F9: bracketed IPv6 addresses are now stripped before comparing against
// the local-hosts set.
test('F9 FIXED: a bracketed IPv6 loopback address is now correctly recognized as local', async () => {
  const results = await assessNetworkExposure({
    detectedAgents: [{ id: 'ollama', label: 'Ollama', defaultPorts: [11434] }],
    listListeningPorts: async () => [{ host: '[::1]', port: 11434, pid: 1 }],
  });
  assert.equal(results.length, 1);
  assert.equal(results[0].externallyBound, false);
});

test('F9: a genuinely externally-bound bracketed IPv6 address is still flagged correctly', async () => {
  const results = await assessNetworkExposure({
    detectedAgents: [{ id: 'ollama', label: 'Ollama', defaultPorts: [11434] }],
    listListeningPorts: async () => [{ host: '[::]', port: 11434, pid: 1 }],
  });
  assert.equal(results[0].externallyBound, true);
});
