import { test } from 'node:test';
import assert from 'node:assert/strict';
import { correlate } from '../src/core/correlation-engine.js';
import { resetDetectionCounter } from '../src/core/detection.js';

let seq = 0;
function ev(overrides) {
  seq += 1;
  return {
    id: `e${seq}`,
    timestamp: `2026-01-01T00:00:${String(seq).padStart(2, '0')}.000Z`,
    actionType: null,
    resource: null,
    decision: 'ALLOW',
    risk: 'LOW',
    rule: null,
    serverName: 'trusted-server',
    destination: null,
    toolName: 'tool',
    ...overrides,
  };
}

test('normal, unrelated actions produce no detections', () => {
  resetDetectionCounter();
  const events = [
    ev({ actionType: 'FILE_READ', resource: 'filesystem:./src/index.js', risk: 'LOW' }),
    ev({ actionType: 'MCP_TOOL_CALL', risk: 'LOW' }),
  ];
  assert.deepEqual(correlate(events, 's1'), []);
});

test('sensitive file read followed by a network request -> HIGH detection', () => {
  resetDetectionCounter();
  const events = [
    ev({ actionType: 'FILE_READ', resource: 'filesystem:.env', risk: 'HIGH' }),
    ev({ actionType: 'NETWORK_REQUEST', destination: 'attacker.example.com', risk: 'MEDIUM' }),
  ];
  const detections = correlate(events, 's1');
  assert.ok(detections.some((d) => d.title === 'Potential sensitive-data exposure pattern' && d.severity === 'HIGH'));
});

test('credential access followed by shell execution -> CRITICAL detection', () => {
  resetDetectionCounter();
  const events = [
    ev({ actionType: 'FILE_READ', resource: 'filesystem:~/.aws/credentials', risk: 'CRITICAL' }),
    ev({ actionType: 'SHELL_EXEC', toolName: 'aws', risk: 'LOW' }),
  ];
  const detections = correlate(events, 's1');
  assert.ok(detections.some((d) => d.title === 'Credential access chain detected' && d.severity === 'CRITICAL'));
});

test('untrusted MCP server followed by sensitive read -> HIGH detection', () => {
  resetDetectionCounter();
  const events = [
    ev({ actionType: 'MCP_TOOL_CALL', rule: 'mcp.allowed_servers', decision: 'WARN', serverName: 'mystery-server' }),
    ev({ actionType: 'FILE_READ', resource: 'filesystem:.env', risk: 'HIGH' }),
  ];
  const detections = correlate(events, 's1');
  assert.ok(detections.some((d) => d.title === 'Untrusted MCP server led to sensitive-resource access'));
});

test('the full 3-step escalation pattern is reported with the observed sequence', () => {
  resetDetectionCounter();
  const events = [
    ev({ actionType: 'MCP_TOOL_CALL', rule: 'mcp.allowed_servers', decision: 'WARN', serverName: 'mystery-server' }),
    ev({ actionType: 'FILE_READ', resource: 'filesystem:.env', risk: 'HIGH' }),
    ev({ actionType: 'NETWORK_REQUEST', destination: 'attacker.example.com' }),
  ];
  const detections = correlate(events, 's1');
  const escalation = detections.find((d) => d.title === 'Potential agent compromise pattern detected');
  assert.ok(escalation);
  assert.equal(escalation.severity, 'CRITICAL');
  assert.match(escalation.description, /1\. Unknown MCP server invoked \(mystery-server\)/);
  assert.match(escalation.description, /2\. Sensitive file targeted/);
  assert.match(escalation.description, /3\. External destination requested \(attacker\.example\.com\)/);
});

test('order matters: a network request BEFORE the sensitive read does not trigger the pattern', () => {
  resetDetectionCounter();
  const events = [
    ev({ actionType: 'NETWORK_REQUEST', destination: 'github.com' }),
    ev({ actionType: 'FILE_READ', resource: 'filesystem:.env', risk: 'HIGH' }),
  ];
  assert.deepEqual(correlate(events, 's1'), []);
});

test('detection ids are sequential across a correlation run', () => {
  resetDetectionCounter();
  const events = [
    ev({ actionType: 'FILE_READ', resource: 'filesystem:~/.aws/credentials', risk: 'CRITICAL' }),
    ev({ actionType: 'SHELL_EXEC', toolName: 'aws' }),
    ev({ actionType: 'NETWORK_REQUEST', destination: 'evil.example.com' }),
  ];
  const detections = correlate(events, 's1');
  assert.ok(detections.length >= 2);
  assert.equal(detections[0].id, 'DETECT-001');
  assert.equal(detections[1].id, 'DETECT-002');
});
