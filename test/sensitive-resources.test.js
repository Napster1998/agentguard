import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { scanSensitiveResources } from '../src/adapters/discovery/sensitive-resources.js';
import { sensitiveResourceFindings } from '../src/core/findings-rules.js';

const SECRET_MARKER = 'AKIA_THIS_SHOULD_NEVER_APPEAR_IN_OUTPUT';

function fakeStat({ isDir }) {
  return { isDirectory: () => isDir, mode: 0o600 };
}

test('identifies ~/.ssh (a directory)', () => {
  const found = scanSensitiveResources({
    homedir: '/fake/home',
    cwd: '/fake/project',
    statSync: (p) => {
      if (p === path.join('/fake/home', '.ssh')) return fakeStat({ isDir: true });
      throw new Error('ENOENT');
    },
  });
  assert.equal(found.length, 1);
  assert.equal(found[0].label, 'SSH directory');
  assert.equal(found[0].severity, 'HIGH');
  assert.equal(found[0].isDirectory, true);
});

test('identifies ~/.aws/credentials as CRITICAL', () => {
  const target = path.join('/fake/home', '.aws', 'credentials');
  const found = scanSensitiveResources({
    homedir: '/fake/home',
    cwd: '/fake/project',
    statSync: (p) => {
      if (p === target) return fakeStat({ isDir: false });
      throw new Error('ENOENT');
    },
  });
  assert.equal(found.length, 1);
  assert.equal(found[0].severity, 'CRITICAL');
});

test('identifies a project .env file', () => {
  const target = path.join('/fake/project', '.env');
  const found = scanSensitiveResources({
    homedir: '/fake/home',
    cwd: '/fake/project',
    statSync: (p) => {
      if (p === target) return fakeStat({ isDir: false });
      throw new Error('ENOENT');
    },
  });
  assert.equal(found.length, 1);
  assert.equal(found[0].label, 'Environment file');
});

test('a resource that does not exist produces nothing (no crash)', () => {
  const found = scanSensitiveResources({
    homedir: '/fake/home',
    cwd: '/fake/project',
    statSync: () => {
      throw new Error('ENOENT');
    },
  });
  assert.deepEqual(found, []);
});

test('findings never expose file contents — only path, mode, severity ever appear', () => {
  // scanSensitiveResources only ever calls statSync, never readFileSync, so
  // it is structurally incapable of seeing this marker; this test locks in
  // that the resulting finding's evidence field only ever contains path/mode.
  const target = path.join('/fake/home', '.aws', 'credentials');
  const found = scanSensitiveResources({
    homedir: '/fake/home',
    cwd: '/fake/project',
    statSync: (p) => {
      if (p === target) return fakeStat({ isDir: false });
      throw new Error('ENOENT');
    },
  });
  const findings = sensitiveResourceFindings(found);
  const serialized = JSON.stringify(findings);
  assert.ok(!serialized.includes(SECRET_MARKER));
  assert.match(findings[0].evidence, /\(file, mode \d+\)$/);
});
