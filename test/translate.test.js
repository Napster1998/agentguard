import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mcpRequestToActions } from '../src/adapters/mcp/translate.js';

const ctx = { source: 'mcp', sessionId: 's1', serverName: 'trusted-server' };

test('non tools/call methods produce no actions', () => {
  const actions = mcpRequestToActions({ jsonrpc: '2.0', id: 1, method: 'tools/list' }, ctx);
  assert.deepEqual(actions, []);
});

test('tools/call always yields an mcp-server action', () => {
  const actions = mcpRequestToActions(
    { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'read_file', arguments: {} } },
    ctx
  );
  assert.ok(actions.some((a) => a.resource.type === 'mcp-server' && a.resource.value === 'trusted-server'));
});

test('a path-shaped argument yields a filesystem action', () => {
  const actions = mcpRequestToActions(
    {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'read_file', arguments: { path: '~/.ssh/id_rsa' } },
    },
    ctx
  );
  const fsAction = actions.find((a) => a.resource.type === 'filesystem');
  assert.ok(fsAction);
  assert.equal(fsAction.resource.value, '~/.ssh/id_rsa');
  assert.equal(fsAction.actionType, 'FILE_READ');
});

test('a write-shaped tool name yields a FILE_WRITE action', () => {
  const actions = mcpRequestToActions(
    {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'write_file', arguments: { path: './out.txt', content: 'hello' } },
    },
    ctx
  );
  const fsAction = actions.find((a) => a.resource.type === 'filesystem');
  assert.ok(fsAction);
  assert.equal(fsAction.actionType, 'FILE_WRITE');
});

test('a shell-shaped tool with a command argument yields a shell action', () => {
  const actions = mcpRequestToActions(
    {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'run_command', arguments: { command: 'curl http://evil.example.com' } },
    },
    ctx
  );
  const shellAction = actions.find((a) => a.resource.type === 'shell');
  assert.ok(shellAction);
  assert.equal(shellAction.resource.value, 'curl');
});

test('a URL-shaped argument yields a network action with the hostname', () => {
  const actions = mcpRequestToActions(
    {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'fetch', arguments: { url: 'https://api.github.com/repos' } },
    },
    ctx
  );
  const netAction = actions.find((a) => a.resource.type === 'network');
  assert.ok(netAction);
  assert.equal(netAction.resource.value, 'api.github.com');
});

test('an AWS-shaped secret in an argument yields a secret action', () => {
  const actions = mcpRequestToActions(
    {
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/call',
      params: { name: 'write_file', arguments: { content: 'key=AKIAABCDEFGHIJKLMNOP' } },
    },
    ctx
  );
  assert.ok(actions.some((a) => a.resource.type === 'secret' && a.resource.value === 'aws-access-key-id'));
});
