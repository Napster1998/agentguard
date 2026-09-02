// Attack Area 11 (resource exhaustion) + Attack Area 3 (malformed requests).
// walkStrings (request side) and collectStrings (response side) recurse
// through nested objects/arrays with NO depth limit - this confirms a
// stack-overflow DoS is real, bounded only by how deep JSON.parse itself
// will construct a structure. It also confirms a set of malformed-but-
// syntactically-valid request shapes do NOT crash the translator (a
// positive finding, not a vulnerability).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mcpRequestToActions } from '../../src/adapters/mcp/translate.js';
import { inspectResponse } from '../../src/adapters/mcp/response-inspect.js';

const ctx = { source: 'mcp', sessionId: 's1', serverName: 'trusted-server' };

function deeplyNested(depth) {
  let obj = { leaf: 'value' };
  for (let i = 0; i < depth; i++) obj = { nested: obj };
  return obj;
}

test('deeply nested request arguments eventually stack-overflow walkStrings (confirmed DoS surface, not fixed here)', () => {
  const deep = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: deeplyNested(200000) } };
  assert.throws(() => mcpRequestToActions(deep, ctx), /Maximum call stack/i);
});

test('deeply nested response content eventually stack-overflow inspectResponse (confirmed DoS surface, not fixed here)', () => {
  const deep = deeplyNested(200000);
  assert.throws(() => inspectResponse(deep), /Maximum call stack/i);
});

test('a moderately nested request/response does NOT crash (bounded, realistic depths are fine)', () => {
  assert.doesNotThrow(() => mcpRequestToActions({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: deeplyNested(50) } }, ctx));
  assert.doesNotThrow(() => inspectResponse(deeplyNested(50)));
});

test('malformed request shapes do not crash the translator (positive finding)', () => {
  const cases = [
    { jsonrpc: '2.0', id: 1, method: 'tools/call' }, // missing params entirely
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: {} }, // missing name/arguments
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 123, arguments: {} } }, // non-string tool name
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: 'not-an-object' } }, // wrong type
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: null } },
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: [1, 2, 3] } }, // array instead of object
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: null } } },
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: { path: 12345 } } }, // non-string value
  ];
  for (const req of cases) {
    assert.doesNotThrow(() => mcpRequestToActions(req, ctx), `should not throw for ${JSON.stringify(req)}`);
  }
});

test('response inspection does not crash on malformed/unusual response shapes', () => {
  const cases = [undefined, null, 'a plain string result', 12345, [1, 2, 3], { weird: { deeply: { but: { shallow: 'ok' } } } }];
  for (const result of cases) {
    assert.doesNotThrow(() => inspectResponse(result));
  }
});
