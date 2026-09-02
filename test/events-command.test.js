import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readEvents, formatEvents } from '../src/cli/events-command.js';

function tempLogFile(events) {
  const file = path.join(os.tmpdir(), `agentguard-events-test-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`);
  fs.writeFileSync(file, events.map((e) => JSON.stringify(e)).join('\n') + '\n');
  return file;
}

test('readEvents returns [] for a log file that does not exist', () => {
  assert.deepEqual(readEvents('/does/not/exist.jsonl'), []);
});

test('readEvents skips malformed lines instead of throwing', () => {
  const file = path.join(os.tmpdir(), `agentguard-events-malformed-${Date.now()}.jsonl`);
  fs.writeFileSync(file, '{ not valid json\n{"sessionId":"s1","decision":"ALLOW","timestamp":"2026-01-01T00:00:00.000Z"}\n');
  const events = readEvents(file);
  assert.equal(events.length, 1);
  assert.equal(events[0].sessionId, 's1');
});

test('formatEvents groups events by sessionId and orders by timestamp', () => {
  const events = [
    { sessionId: 's1', decision: 'ALLOW', risk: 'LOW', timestamp: '2026-01-01T00:00:02.000Z', toolName: 'read_file', resource: 'filesystem:./b.js', reason: '' },
    { sessionId: 's1', decision: 'BLOCK', risk: 'CRITICAL', timestamp: '2026-01-01T00:00:01.000Z', toolName: 'read_file', resource: 'filesystem:~/.ssh/id_rsa', reason: 'blocked' },
    { sessionId: 's2', decision: 'ALLOW', risk: 'LOW', timestamp: '2026-01-01T00:00:00.000Z', toolName: 'read_file', resource: 'filesystem:./a.js', reason: '' },
  ];
  const output = formatEvents(events);
  const s1Index = output.indexOf('Session s1');
  const s2Index = output.indexOf('Session s2');
  assert.ok(s1Index !== -1 && s2Index !== -1);
  // Within session s1, the earlier (BLOCK) event must appear before the later (ALLOW) one.
  const blockIndex = output.indexOf('id_rsa');
  const allowIndex = output.indexOf('b.js');
  assert.ok(blockIndex < allowIndex);
});

test('formatEvents --session filters to just that session', () => {
  const events = [
    { sessionId: 's1', decision: 'ALLOW', risk: 'LOW', timestamp: '2026-01-01T00:00:00.000Z', toolName: 't', resource: 'r', reason: '' },
    { sessionId: 's2', decision: 'ALLOW', risk: 'LOW', timestamp: '2026-01-01T00:00:00.000Z', toolName: 't', resource: 'r', reason: '' },
  ];
  const output = formatEvents(events, { sessionId: 's2' });
  assert.ok(!output.includes('Session s1'));
  assert.ok(output.includes('Session s2'));
});

test('end-to-end: readEvents + formatEvents over a real temp log file', () => {
  const file = tempLogFile([
    { sessionId: 'abc', decision: 'WARN', risk: 'HIGH', timestamp: '2026-01-01T00:00:00.000Z', toolName: 'read_file', resource: 'filesystem:.env', reason: 'watched pattern' },
  ]);
  const events = readEvents(file);
  const output = formatEvents(events);
  assert.match(output, /Session abc/);
  assert.match(output, /\[WARN\]/);
  fs.unlinkSync(file);
});
