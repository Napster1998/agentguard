// F10 (MEDIUM, FIXED): found by running the real gateway in front of a real
// Burp Suite MCP bridge, not by unit tests. Burp's send_http1_request /
// create_repeater_tab take a bare `targetHostname` plus raw HTTP text. The
// translator only recognized a network destination when a value started with
// `scheme://`, so:
//   - `targetHostname` matched PATH_KEY_RE (it contains "target") and was
//     filed as a FILESYSTEM path;
//   - the raw HTTP request text contained "/" and was ALSO filed as a path;
//   - the real destination never became a network action, so
//     network.allowed_domains never applied and the call was ALLOWed.
// Fix: keys that end in host/hostname/domain are network destinations, and
// raw HTTP request text contributes its Host header (or absolute-form
// request target). Still best-effort - see the residual-gap test below.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mcpRequestToActions } from '../../src/adapters/mcp/translate.js';
import { PolicyEngine, applyDefaults } from '../../src/core/policy-engine.js';

const ctx = { source: 'mcp', sessionId: 's1', serverName: 'burpsuite' };

// Exact argument shape from Burp's real tool schema (send_http1_request).
const burpArgs = (host) => ({
  content: `GET / HTTP/1.1\r\nHost: ${host}\r\n\r\n`,
  targetHostname: host,
  targetPort: 80,
  usesHttps: false,
});

function translate(name, args) {
  return mcpRequestToActions({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } }, ctx);
}
const networkHosts = (actions) => actions.filter((a) => a.resource.type === 'network').map((a) => a.resource.value);
const fsValues = (actions) => actions.filter((a) => a.resource.type === 'filesystem').map((a) => a.resource.value);

test('F10a FIXED: Burp send_http1_request destination is a network action, not a filesystem path', () => {
  const actions = translate('send_http1_request', burpArgs('attacker.invalid'));
  assert.deepEqual(networkHosts(actions), ['attacker.invalid'], 'one network action; targetHostname and Host header deduplicated');
  assert.deepEqual(fsValues(actions), [], 'neither the hostname nor the raw HTTP text is a filesystem path');
});

test('F10b FIXED: end-to-end - an unlisted destination now WARNs via network.allowed_domains; a listed one does not', () => {
  const engine = new PolicyEngine(applyDefaults({ mcp: { allowed_servers: ['burpsuite'] }, network: { allowed_domains: ['github.com'] } }));
  const verdictFor = (host) => {
    const decisions = translate('send_http1_request', burpArgs(host)).map((a) => engine.evaluate(a));
    return decisions.find((d) => d.verdict !== 'ALLOW') || decisions[0];
  };
  const unlisted = verdictFor('attacker.invalid');
  assert.equal(unlisted.verdict, 'WARN');
  assert.match(unlisted.reason, /attacker\.invalid/);
  assert.equal(verdictFor('github.com').verdict, 'ALLOW');
});

test('F10c FIXED: destination carried only in the raw HTTP Host header is still extracted (with port stripped)', () => {
  const actions = translate('create_repeater_tab', { tabName: 't', content: 'POST /x HTTP/1.1\r\nHost: Attacker.Invalid:8080\r\nContent-Length: 0\r\n\r\n' });
  assert.deepEqual(networkHosts(actions), ['attacker.invalid']);
});

test('F10d FIXED: absolute-form request target in raw HTTP text is extracted', () => {
  const actions = translate('send_http1_request', { content: 'GET http://attacker.invalid/p HTTP/1.1\r\n\r\n' });
  assert.deepEqual(networkHosts(actions), ['attacker.invalid']);
});

test('F10e FIXED: host/hostname/domain-style keys carry a network destination; a port suffix is stripped', () => {
  for (const key of ['host', 'hostname', 'targetHostname', 'target_host', 'domain']) {
    assert.deepEqual(networkHosts(translate('probe', { [key]: 'attacker.invalid:8443' })), ['attacker.invalid'], key);
  }
});

test('F10f no regression: path-style keys (including ones containing "target") are still filesystem', () => {
  for (const key of ['path', 'target_path', 'targetDir', 'file']) {
    const actions = translate('read_file', { [key]: './src/a.js' });
    assert.deepEqual(fsValues(actions), ['./src/a.js'], key);
    assert.deepEqual(networkHosts(actions), [], key);
  }
  // a host-looking key whose value is clearly not a hostname falls through to the old behavior, no crash
  assert.deepEqual(networkHosts(translate('probe', { host: '../etc/passwd' })), []);
  assert.deepEqual(fsValues(translate('probe', { host: '../etc/passwd' })), ['../etc/passwd']);
});

test('F10g RESIDUAL GAP (documented, not fixed): a destination under an unrelated key name is still not recognized as network', () => {
  // Deliberately asserts the CURRENT limitation so it can't be silently
  // forgotten or over-claimed. Classification is by key name and value
  // shape; a tool that hides its target in an arbitrary field evades it.
  const actions = translate('probe', { dest: 'attacker.invalid' });
  assert.deepEqual(networkHosts(actions), []);
});
