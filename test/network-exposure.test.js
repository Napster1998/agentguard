import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessNetworkExposure } from '../src/adapters/discovery/network-exposure.js';

const agents = [{ id: 'ollama', label: 'Ollama', defaultPorts: [11434] }];

test('a localhost-only bound service is not flagged as externally bound', async () => {
  const results = await assessNetworkExposure({
    detectedAgents: agents,
    listListeningPorts: async () => [{ host: '127.0.0.1', port: 11434, pid: 1 }],
  });
  assert.equal(results.length, 1);
  assert.equal(results[0].externallyBound, false);
});

test('a service bound to 0.0.0.0 is flagged as externally bound', async () => {
  const results = await assessNetworkExposure({
    detectedAgents: agents,
    listListeningPorts: async () => [{ host: '0.0.0.0', port: 11434, pid: 1 }],
  });
  assert.equal(results.length, 1);
  assert.equal(results[0].externallyBound, true);
});

test('only ports belonging to a detected agent are considered (not a general port scan)', async () => {
  const results = await assessNetworkExposure({
    detectedAgents: agents,
    listListeningPorts: async () => [{ host: '0.0.0.0', port: 9999, pid: 2 }],
  });
  assert.deepEqual(results, []);
});
