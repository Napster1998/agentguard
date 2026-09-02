// F7 (MEDIUM, FIXED): readEvents()/formatEvents()/correlate() used to sort
// on `.timestamp` without checking it exists, so a single malformed-but-
// valid-JSON log line anywhere crashed the entire `agentguard events`
// report. Both formatEvents' own sort and readEvents' normalization now
// default a missing timestamp instead of throwing.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { formatEvents, readEvents } from '../../src/cli/events-command.js';
import { correlate } from '../../src/core/correlation-engine.js';

test('F7 baseline: well-formed events render fine', () => {
  const events = [
    { sessionId: 's1', decision: 'ALLOW', risk: 'LOW', timestamp: '2026-01-01T00:00:00.000Z', toolName: 't', resource: 'r', reason: '' },
  ];
  assert.doesNotThrow(() => formatEvents(events));
});

test('F7 FIXED: an event missing `timestamp` no longer crashes the report — other sessions still render', () => {
  const events = [
    { sessionId: 's1', decision: 'ALLOW', risk: 'LOW', timestamp: '2026-01-01T00:00:00.000Z', toolName: 't', resource: 'r', reason: '' },
    { sessionId: 's2', decision: 'ALLOW', risk: 'LOW', timestamp: '2026-01-01T00:00:00.000Z', toolName: 't2a', resource: 'r2a', reason: '' },
    { sessionId: 's2', decision: 'BLOCK', risk: 'CRITICAL', toolName: 't2b', resource: 'r2b', reason: 'x' }, // no timestamp
  ];
  let output;
  assert.doesNotThrow(() => {
    output = formatEvents(events);
  });
  assert.match(output, /Session s1/);
  assert.match(output, /Session s2/);
  assert.match(output, /t2b/, 'the malformed event itself still renders, just sorted as earliest');
});

test('F7 FIXED: correlate() also tolerates a missing timestamp', () => {
  const events = [
    { id: 'e1', sessionId: 's1', decision: 'WARN', risk: 'HIGH', actionType: 'FILE_READ', resource: 'filesystem:.env' }, // no timestamp
    { id: 'e2', sessionId: 's1', decision: 'ALLOW', risk: 'LOW', actionType: 'NETWORK_REQUEST', destination: 'evil.example.com', timestamp: '2026-01-01T00:00:01.000Z' },
  ];
  assert.doesNotThrow(() => correlate(events, 's1'));
});

test('F7 FIXED: readEvents() normalizes a missing timestamp when reading from a real file', () => {
  const file = path.join(os.tmpdir(), `agentguard-f7-${Date.now()}.jsonl`);
  fs.writeFileSync(file, JSON.stringify({ sessionId: 's1', decision: 'ALLOW' }) + '\n');
  const events = readEvents(file);
  assert.equal(events.length, 1);
  assert.equal(events[0].timestamp, '');
  fs.unlinkSync(file);
});
