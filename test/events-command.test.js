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

test('--risk filters displayed events but a pattern spanning multiple risk levels is still detected', () => {
  const events = [
    {
      sessionId: 's1', agentId: 'agent-x', decision: 'WARN', risk: 'MEDIUM', timestamp: '2026-01-01T00:00:01.000Z',
      toolName: 'read_file', resource: 'mcp-server:mystery-server', reason: '', actionType: 'MCP_TOOL_CALL',
      rule: 'mcp.allowed_servers', serverName: 'mystery-server',
    },
    {
      sessionId: 's1', agentId: 'agent-x', decision: 'WARN', risk: 'HIGH', timestamp: '2026-01-01T00:00:02.000Z',
      toolName: 'read_file', resource: 'filesystem:.env', reason: '', actionType: 'FILE_READ',
    },
    {
      sessionId: 's1', agentId: 'agent-x', decision: 'ALLOW', risk: 'LOW', timestamp: '2026-01-01T00:00:03.000Z',
      toolName: 'fetch', resource: 'network:evil.example.com', destination: 'evil.example.com', reason: '', actionType: 'NETWORK_REQUEST',
    },
  ];

  // Filtering the *display* to only HIGH-risk events must not suppress the
  // escalation detection, which depends on the MEDIUM-risk first step too.
  const output = formatEvents(events, { risk: 'HIGH' });
  assert.match(output, /Potential agent compromise pattern detected/);
  assert.match(output, /Agent: agent-x/);
  // And the display itself really was filtered: only the HIGH-risk line shows.
  assert.ok(!output.includes('mcp-server:mystery-server'));
  assert.match(output, /filesystem:\.env/);
});

test('--blocked shows only BLOCK-decision events', () => {
  const events = [
    { sessionId: 's1', decision: 'ALLOW', risk: 'LOW', timestamp: '2026-01-01T00:00:01.000Z', toolName: 't1', resource: 'r1', reason: '' },
    { sessionId: 's1', decision: 'BLOCK', risk: 'CRITICAL', timestamp: '2026-01-01T00:00:02.000Z', toolName: 't2', resource: 'r2', reason: 'nope' },
  ];
  const output = formatEvents(events, { blockedOnly: true });
  assert.ok(!output.includes('r1'));
  assert.match(output, /r2/);
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
