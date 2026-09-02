import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import { matchesAny } from '../src/core/glob-match.js';

test('matches a literal-tilde path against a ~-prefixed pattern', () => {
  assert.equal(matchesAny('~/.ssh/id_rsa', ['~/.ssh/**']), '~/.ssh/**');
});

test('matches an absolute resolved home-dir path against a ~-prefixed pattern', () => {
  const abs = os.homedir().replace(/\\/g, '/') + '/.ssh/id_rsa';
  assert.equal(matchesAny(abs, ['~/.ssh/**']), '~/.ssh/**');
});

test('does not match an unrelated path', () => {
  assert.equal(matchesAny('./src/index.js', ['~/.ssh/**', '~/.aws/**']), null);
});

test('exact ".env" pattern matches only the bare file', () => {
  assert.equal(matchesAny('.env', ['.env']), '.env');
  assert.equal(matchesAny('.env.local', ['.env']), null);
});

test('".env.*" pattern matches variants but not the bare file', () => {
  assert.equal(matchesAny('.env.local', ['.env.*']), '.env.*');
  assert.equal(matchesAny('.env', ['.env.*']), null);
});

test('"**" matches across nested directories', () => {
  assert.equal(matchesAny('~/.aws/nested/dir/credentials', ['~/.aws/**']), '~/.aws/**');
});

test('matching is case-insensitive', () => {
  assert.equal(matchesAny('~/.SSH/ID_RSA', ['~/.ssh/**']), '~/.ssh/**');
});
