import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  classifyEntry, isWrappedEntry, buildWrappedEntry, buildUnwrappedEntry, planServers, wrapperPrefix,
} from '../src/adapters/wrap/plan.js';

const ctx = {
  nodePath: '/usr/bin/node',
  scriptPath: '/opt/agentguard/bin/agentguard.js',
  policyPath: '/home/u/.agentguard/policy.yaml',
  logPath: '/home/u/.agentguard/audit.jsonl',
};
const plain = { command: 'npx', args: ['-y', '@scope/server', '/home/u'], env: { TOKEN: 'x' } };

test('classifies a plain stdio entry as unwrapped', () => {
  assert.equal(classifyEntry('fs', plain, ctx).state, 'unwrapped');
});

test('remote servers (url or sse/http transport) are skipped with a reason, never wrapped', () => {
  assert.equal(classifyEntry('r', { url: 'https://x.example/mcp' }, ctx).state, 'remote');
  assert.equal(classifyEntry('r', { transport: 'SSE', command: 'x' }, ctx).state, 'remote');
  assert.match(classifyEntry('r', { url: 'https://x' }, ctx).reason, /unprotected/);
});

test('invalid entries are reported, never crash', () => {
  for (const bad of [null, 'str', [], {}, { command: '' }, { command: 'x', args: 'notalist' }, { command: 'x', args: [1] }]) {
    assert.equal(classifyEntry('b', bad, ctx).state, 'invalid', JSON.stringify(bad));
  }
});

test('wrapping preserves every other key and puts the original command after "--"', () => {
  const w = buildWrappedEntry('fs', plain, ctx);
  assert.equal(w.command, ctx.nodePath);
  assert.deepEqual(w.env, { TOKEN: 'x' });
  assert.deepEqual(w.args, [...wrapperPrefix('fs', ctx), 'npx', '-y', '@scope/server', '/home/u']);
  assert.deepEqual(Object.keys(w), ['command', 'args', 'env'], 'key order preserved');
  assert.ok(isWrappedEntry(w));
  assert.equal(classifyEntry('fs', w, ctx).state, 'wrapped');
});

test('round trip: unwrap(wrap(x)) restores the original entry exactly', () => {
  assert.deepEqual(buildUnwrappedEntry(buildWrappedEntry('fs', plain, ctx)), plain);
  const noArgs = { command: 'my-server' };
  assert.deepEqual(buildUnwrappedEntry(buildWrappedEntry('s', noArgs, ctx)), noArgs, 'absent args stays absent');
});

test('idempotent: an already-wrapped entry is planned as skip, not double-wrapped', () => {
  const wrapped = buildWrappedEntry('fs', plain, ctx);
  const [p] = planServers({ fs: wrapped }, 'wrap', ctx);
  assert.equal(p.state, 'wrapped');
  assert.equal(p.action, 'skip');
  assert.deepEqual(buildWrappedEntry('fs', wrapped, ctx), wrapped, 'even a forced re-wrap is a no-op');
});

test('stale wrapper (moved repo / new node) is detected and repaired while keeping the original command', () => {
  const old = buildWrappedEntry('fs', plain, { ...ctx, nodePath: 'C:/old/node.exe', scriptPath: '/gone/agentguard.js' });
  assert.equal(classifyEntry('fs', old, ctx).state, 'stale');
  const [p] = planServers({ fs: old }, 'wrap', ctx);
  assert.equal(p.action, 'repair');
  assert.deepEqual(p.after, buildWrappedEntry('fs', plain, ctx));
});

test('a different policy path also counts as stale', () => {
  const old = buildWrappedEntry('fs', plain, { ...ctx, policyPath: '/elsewhere/policy.yaml' });
  assert.equal(classifyEntry('fs', old, ctx).state, 'stale');
});

test('unwrap mode only touches ours; wrap mode leaves remote/invalid alone', () => {
  const table = { a: plain, b: { url: 'https://x' }, c: buildWrappedEntry('c', plain, ctx), d: {} };
  const unwrapPlan = Object.fromEntries(planServers(table, 'unwrap', ctx).map((p) => [p.name, p.action]));
  assert.deepEqual(unwrapPlan, { a: 'skip', b: 'skip', c: 'unwrap', d: 'skip' });
  const wrapPlan = Object.fromEntries(planServers(table, 'wrap', ctx).map((p) => [p.name, p.action]));
  assert.deepEqual(wrapPlan, { a: 'wrap', b: 'skip', c: 'skip', d: 'skip' });
});

test('a lookalike (an args[1] of "gateway" but not our script) is NOT treated as ours', () => {
  assert.equal(isWrappedEntry({ command: 'x', args: ['other.js', 'gateway', '--', 'cmd'] }), false);
  assert.equal(isWrappedEntry({ command: 'x', args: ['agentguard.js', 'gateway', '--'] }), false, 'nothing after "--"');
});
