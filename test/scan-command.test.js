import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formatScanReport } from '../src/cli/scan-command.js';
import { createPosture } from '../src/core/security-posture.js';
import { createFinding, resetFindingCounters } from '../src/core/security-finding.js';

test('formatScanReport renders detected agents, MCP servers, and severity counts', () => {
  resetFindingCounters();
  const posture = createPosture({
    discoveredAgents: [{ id: 'ollama', label: 'Ollama', detectedVia: 'process' }],
    discoveredMcpServers: [
      { name: 'github-mcp', trust: 'trusted' },
      { name: 'custom-server', trust: 'unknown' },
    ],
    findings: [
      createFinding({ category: 'fs', title: 'AWS credentials potentially accessible', severity: 'CRITICAL', description: 'd', evidence: 'e', recommendation: 'r' }),
      createFinding({ category: 'net', title: 'Ollama exposed beyond localhost', severity: 'HIGH', description: 'd', evidence: 'e', recommendation: 'r' }),
    ],
  });

  const report = formatScanReport(posture);

  assert.match(report, /Ollama detected/);
  assert.match(report, /github-mcp\s+TRUSTED/);
  assert.match(report, /custom-server\s+UNKNOWN/);
  assert.match(report, /AWS credentials potentially accessible/);
  assert.match(report, /CRITICAL\s+1/);
  assert.match(report, /HIGH\s+1/);
  assert.match(report, /Overall: HIGH RISK/);
});

test('formatScanReport handles an empty posture without crashing', () => {
  const posture = createPosture({});
  const report = formatScanReport(posture);
  assert.match(report, /no known local AI\/agent runtime detected/);
  assert.match(report, /Overall: LOW RISK/);
});
