import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectAgents } from '../src/adapters/discovery/agent-detection.js';

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
