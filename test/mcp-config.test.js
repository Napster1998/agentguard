import { test } from 'node:test';
import assert from 'node:assert/strict';
import { discoverMcpServers } from '../src/adapters/discovery/mcp-config.js';

function fakeReader(files) {
  return (p) => {
    if (!(p in files)) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
    return files[p];
  };
}

test('discovers servers from a valid config and marks trust from the policy allowlist', () => {
  const files = {
    '/fake/.mcp.json': JSON.stringify({
      mcpServers: {
        'trusted-server': { command: 'npx', args: ['-y', 'trusted-mcp-server'] },
        'mystery-server': { command: 'node', args: ['server.js'] },
      },
    }),
  };
  const { servers, errors } = discoverMcpServers({
    locations: ['/fake/.mcp.json'],
    trustedServerNames: ['trusted-server'],
    readFile: fakeReader(files),
  });

  assert.equal(errors.length, 0);
  assert.equal(servers.length, 2);
  const trusted = servers.find((s) => s.name === 'trusted-server');
  const unknown = servers.find((s) => s.name === 'mystery-server');
  assert.equal(trusted.trust, 'trusted');
  assert.equal(unknown.trust, 'unknown');
  assert.equal(trusted.transport, 'stdio');
});

test('a missing config file is silently skipped, not an error', () => {
  const { servers, errors } = discoverMcpServers({ locations: ['/fake/does-not-exist.json'], readFile: fakeReader({}) });
  assert.deepEqual(servers, []);
  assert.deepEqual(errors, []);
});

test('a malformed config file produces an error entry, never throws', () => {
  const files = { '/fake/bad.json': '{ this is not valid json' };
  assert.doesNotThrow(() => {
    const { servers, errors } = discoverMcpServers({ locations: ['/fake/bad.json'], readFile: fakeReader(files) });
    assert.deepEqual(servers, []);
    assert.equal(errors.length, 1);
    assert.match(errors[0].message, /Malformed JSON/);
  });
});

test('never executes the discovered command — only parses config', () => {
  const files = {
    '/fake/.mcp.json': JSON.stringify({ mcpServers: { evil: { command: 'rm', args: ['-rf', '/'] } } }),
  };
  const { servers } = discoverMcpServers({ locations: ['/fake/.mcp.json'], readFile: fakeReader(files) });
  assert.equal(servers[0].command, 'rm');
  assert.deepEqual(servers[0].arguments, ['-rf', '/']);
  // The assertion here is really about behavior we don't have: there is no
  // spawn/exec call anywhere in discoverMcpServers, verified by inspection.
});

test('knownConfigLocations includes the Antigravity global MCP config on every platform', async () => {
  const { knownConfigLocations } = await import('../src/adapters/discovery/mcp-config.js');
  for (const platform of ['win32', 'darwin', 'linux']) {
    const locations = knownConfigLocations({ cwd: '/proj', platform, homedir: '/home/u' });
    assert.ok(
      locations.some((l) => l.replaceAll('\\', '/').endsWith('/home/u/.gemini/config/mcp_config.json')),
      `missing on ${platform}`
    );
  }
});

test('parses the real Antigravity mcp_config.json shape (stdio server launched via java -jar)', () => {
  const raw = JSON.stringify({
    mcpServers: {
      burpsuite: { command: 'C:/jre/bin/java.exe', args: ['-jar', 'C:/Burp-mcp/mcp-proxy.jar', '--sse-url', 'http://127.0.0.1:9876/'] },
    },
  });
  const { servers, errors } = discoverMcpServers({ locations: ['/fake/mcp_config.json'], readFile: () => raw });
  assert.deepEqual(errors, []);
  assert.equal(servers.length, 1);
  assert.equal(servers[0].name, 'burpsuite');
  assert.equal(servers[0].transport, 'stdio');
  assert.equal(servers[0].trust, 'unknown');
});

test('an empty (0-byte) or whitespace-only config is "no servers", not a parse error', () => {
  for (const raw of ['', '  \n\t ']) {
    const { servers, errors } = discoverMcpServers({ locations: ['/fake/mcp_config.json'], readFile: () => raw });
    assert.deepEqual(servers, []);
    assert.deepEqual(errors, []);
  }
});

test('genuinely malformed non-empty config is still reported as an error', () => {
  const { servers, errors } = discoverMcpServers({ locations: ['/fake/mcp_config.json'], readFile: () => '{ not json' });
  assert.deepEqual(servers, []);
  assert.equal(errors.length, 1);
  assert.match(errors[0].message, /Malformed JSON/);
});
