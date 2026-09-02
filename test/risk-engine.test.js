import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessRisk } from '../src/core/risk-engine.js';
import { RISK } from '../src/core/risk.js';
import { VERDICT } from '../src/core/decision.js';
import { PolicyEngine, applyDefaults } from '../src/core/policy-engine.js';
import { createAction } from '../src/core/action.js';

// The five worked examples from the Phase 2 brief (2F), reproduced exactly
// by the same PolicyEngine + RiskEngine used at runtime — not hardcoded
// specially for this test.

const policy = applyDefaults({
  filesystem: { deny: ['~/.aws/**'], warn: ['.env', '.env.*'] },
  mcp: { allowed_servers: ['trusted-server'] },
});
const engine = new PolicyEngine(policy);
const ctx = { source: 'mcp', sessionId: 's1', serverName: 'trusted-server' };

test('example 1: read ./src/auth.ts -> ALLOW, LOW', () => {
  const d = engine.evaluate(createAction({ verb: 'read', resourceType: 'filesystem', resourceValue: './src/auth.ts', context: ctx }));
  assert.equal(d.verdict, VERDICT.ALLOW);
  assert.equal(d.risk, RISK.LOW);
});

test('example 2: read .env -> WARN, HIGH', () => {
  const d = engine.evaluate(createAction({ verb: 'read', resourceType: 'filesystem', resourceValue: '.env', context: ctx }));
  assert.equal(d.verdict, VERDICT.WARN);
  assert.equal(d.risk, RISK.HIGH);
});

test('example 3: read ~/.aws/credentials -> BLOCK, CRITICAL', () => {
  const d = engine.evaluate(createAction({ verb: 'read', resourceType: 'filesystem', resourceValue: '~/.aws/credentials', context: ctx }));
  assert.equal(d.verdict, VERDICT.BLOCK);
  assert.equal(d.risk, RISK.CRITICAL);
});

test('example 4: invoke trusted MCP tool -> ALLOW, LOW', () => {
  const d = engine.evaluate(createAction({ verb: 'invoke', resourceType: 'mcp-server', resourceValue: 'trusted-server', context: ctx }));
  assert.equal(d.verdict, VERDICT.ALLOW);
  assert.equal(d.risk, RISK.LOW);
});

test('example 5: invoke unknown MCP server -> WARN, MEDIUM or HIGH', () => {
  const d = engine.evaluate(createAction({ verb: 'invoke', resourceType: 'mcp-server', resourceValue: 'mystery-server', context: ctx }));
  assert.equal(d.verdict, VERDICT.WARN);
  assert.ok([RISK.MEDIUM, RISK.HIGH].includes(d.risk));
});

test('assessRisk: a credential match always forces CRITICAL regardless of verdict', () => {
  assert.equal(assessRisk({ sensitivity: RISK.LOW, verdict: VERDICT.ALLOW, credentialInvolved: true }), RISK.CRITICAL);
});

test('assessRisk: BLOCK is never reported below HIGH', () => {
  assert.equal(assessRisk({ sensitivity: RISK.NONE, verdict: VERDICT.BLOCK }), RISK.HIGH);
});

test('assessRisk: WARN is never reported below MEDIUM', () => {
  assert.equal(assessRisk({ sensitivity: RISK.NONE, verdict: VERDICT.WARN }), RISK.MEDIUM);
});

test('assessRisk: ALLOW floors at LOW even for a NONE-sensitivity resource', () => {
  assert.equal(assessRisk({ sensitivity: RISK.NONE, verdict: VERDICT.ALLOW }), RISK.LOW);
});
