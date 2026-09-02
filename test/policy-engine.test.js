import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PolicyEngine, applyDefaults } from '../src/core/policy-engine.js';
import { createAction } from '../src/core/action.js';
import { VERDICT } from '../src/core/decision.js';

const policy = applyDefaults({
  filesystem: {
    allow: [],
    deny: ['~/.ssh/**', '~/.aws/**', '~/.aws/credentials'],
    warn: ['.env', '.env.*'],
  },
  shell: { allowed: ['git', 'npm'] },
  mcp: { allowed_servers: ['trusted-server'] },
  network: { allowed_domains: ['github.com'] },
  secrets: { block_exfiltration: true },
});

const engine = new PolicyEngine(policy);
const ctx = { source: 'mcp', sessionId: 's1', serverName: 'trusted-server' };

function fsAction(value) {
  return createAction({ verb: 'read', resourceType: 'filesystem', resourceValue: value, context: ctx });
}

test('allowed action: read a normal source file -> ALLOW', () => {
  const d = engine.evaluate(fsAction('./src/index.js'));
  assert.equal(d.verdict, VERDICT.ALLOW);
});

test('sensitive file: read ~/.ssh/id_rsa -> BLOCK', () => {
  const d = engine.evaluate(fsAction('~/.ssh/id_rsa'));
  assert.equal(d.verdict, VERDICT.BLOCK);
  assert.equal(d.rule, 'filesystem.deny');
});

test('cloud credential: read ~/.aws/credentials -> BLOCK', () => {
  const d = engine.evaluate(fsAction('~/.aws/credentials'));
  assert.equal(d.verdict, VERDICT.BLOCK);
});

test('environment file: read .env -> WARN (documented default, not BLOCK)', () => {
  const d = engine.evaluate(fsAction('.env'));
  assert.equal(d.verdict, VERDICT.WARN);
  assert.equal(d.rule, 'filesystem.warn');
});

test('normal MCP tool: invoke trusted server -> ALLOW', () => {
  const d = engine.evaluate(
    createAction({ verb: 'invoke', resourceType: 'mcp-server', resourceValue: 'trusted-server', context: ctx })
  );
  assert.equal(d.verdict, VERDICT.ALLOW);
});

test('unknown MCP server -> WARN', () => {
  const d = engine.evaluate(
    createAction({ verb: 'invoke', resourceType: 'mcp-server', resourceValue: 'mystery-server', context: ctx })
  );
  assert.equal(d.verdict, VERDICT.WARN);
  assert.equal(d.rule, 'mcp.allowed_servers');
});

test('shell: allowed binary -> ALLOW', () => {
  const d = engine.evaluate(createAction({ verb: 'execute', resourceType: 'shell', resourceValue: 'git', context: ctx }));
  assert.equal(d.verdict, VERDICT.ALLOW);
});

test('shell: unlisted binary -> BLOCK', () => {
  const d = engine.evaluate(createAction({ verb: 'execute', resourceType: 'shell', resourceValue: 'curl', context: ctx }));
  assert.equal(d.verdict, VERDICT.BLOCK);
  assert.equal(d.risk, 'HIGH');
});

test('network: allowed domain -> ALLOW', () => {
  const d = engine.evaluate(createAction({ verb: 'network', resourceType: 'network', resourceValue: 'github.com', context: ctx }));
  assert.equal(d.verdict, VERDICT.ALLOW);
});

test('network: unlisted domain -> WARN', () => {
  const d = engine.evaluate(createAction({ verb: 'network', resourceType: 'network', resourceValue: 'evil.example.com', context: ctx }));
  assert.equal(d.verdict, VERDICT.WARN);
});

test('secret pattern detected -> BLOCK', () => {
  const d = engine.evaluate(
    createAction({ verb: 'transmit', resourceType: 'secret', resourceValue: 'aws-access-key-id', context: ctx })
  );
  assert.equal(d.verdict, VERDICT.BLOCK);
  assert.equal(d.risk, 'CRITICAL');
});

test('empty allowed_servers means all servers trusted', () => {
  const openPolicy = applyDefaults({});
  const openEngine = new PolicyEngine(openPolicy);
  const d = openEngine.evaluate(
    createAction({ verb: 'invoke', resourceType: 'mcp-server', resourceValue: 'anything', context: ctx })
  );
  assert.equal(d.verdict, VERDICT.ALLOW);
});

test('empty shell.allowed blocks all shell execution (secure by default)', () => {
  const openPolicy = applyDefaults({});
  const openEngine = new PolicyEngine(openPolicy);
  const d = openEngine.evaluate(createAction({ verb: 'execute', resourceType: 'shell', resourceValue: 'git', context: ctx }));
  assert.equal(d.verdict, VERDICT.BLOCK);
});
