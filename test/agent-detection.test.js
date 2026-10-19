import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectAgents } from '../src/adapters/discovery/agent-detection.js';
import { KNOWN_AGENTS } from '../src/adapters/discovery/known-agents.js';

const registry = [
  { id: 'ollama', label: 'Ollama', processNamePatterns: [/ollama/i], binaryNames: ['ollama'], defaultPorts: [11434] },
];

test('detects a known agent via a matching running process', async () => {
  const detections = await detectAgents({
    registry,
    listProcesses: async () => [{ pid: 123, name: 'ollama.exe' }],
    findOnPath: async () => null,
  });
  assert.equal(detections.length, 1);
  assert.equal(detections[0].id, 'ollama');
  assert.equal(detections[0].detectedVia, 'process');
  assert.match(detections[0].evidence, /pid 123/);
});

test('falls back to a PATH lookup when no process matches', async () => {
  const detections = await detectAgents({
    registry,
    listProcesses: async () => [],
    findOnPath: async (bin) => (bin === 'ollama' ? '/usr/local/bin/ollama' : null),
  });
  assert.equal(detections.length, 1);
  assert.equal(detections[0].detectedVia, 'path');
});

test('missing runtime: no process match and no PATH hit -> empty result, no crash', async () => {
  const detections = await detectAgents({
    registry,
    listProcesses: async () => [{ pid: 1, name: 'explorer.exe' }],
    findOnPath: async () => null,
  });
  assert.deepEqual(detections, []);
});

test('real registry: detects Google Antigravity from its Windows process name', async () => {
  const detections = await detectAgents({
    registry: KNOWN_AGENTS,
    listProcesses: async () => [{ pid: 4242, name: 'Antigravity.exe' }],
    findOnPath: async () => null,
  });
  const antigravity = detections.find((d) => d.id === 'antigravity');
  assert.ok(antigravity);
  assert.equal(antigravity.label, 'Google Antigravity');
  assert.equal(antigravity.detectedVia, 'process');
});
