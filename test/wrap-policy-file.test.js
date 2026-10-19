import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import yaml from 'js-yaml';
import { ensurePolicy } from '../src/adapters/wrap/policy-file.js';

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'ag-pol-'));
}
const cleanup = (d) => fs.rmSync(d, { recursive: true, force: true });
const load = (f) => yaml.load(fs.readFileSync(f, 'utf8'));

test('first run: creates the policy from the shipped defaults with the approved names filled in', () => {
  const d = tmp();
  try {
    const policyPath = path.join(d, 'home', 'policy.yaml');
    const r = ensurePolicy({ policyPath, names: ['burp', 'burpsuite', 'burp'], backupDir: path.join(d, 'bk') });
    assert.equal(r.created, true);
    const p = load(policyPath);
    assert.deepEqual(p.mcp.allowed_servers, ['burp', 'burpsuite'], 'deduplicated');
    assert.equal(p.shell.block_interpreter_eval, true, 'the rest of the default policy is intact');
    assert.equal(p.secrets.block_exfiltration, true);
  } finally {
    cleanup(d);
  }
});

test('a second run with the same names is a no-op', () => {
  const d = tmp();
  try {
    const policyPath = path.join(d, 'policy.yaml');
    ensurePolicy({ policyPath, names: ['a'], backupDir: path.join(d, 'bk') });
    const before = fs.readFileSync(policyPath, 'utf8');
    const r = ensurePolicy({ policyPath, names: ['a'], backupDir: path.join(d, 'bk') });
    assert.deepEqual([r.created, r.updated, r.notice], [false, false, null]);
    assert.equal(fs.readFileSync(policyPath, 'utf8'), before);
  } finally {
    cleanup(d);
  }
});

test('new names are ADDED to an existing one-line list, with a backup, and nothing else changes', () => {
  const d = tmp();
  try {
    const policyPath = path.join(d, 'policy.yaml');
    ensurePolicy({ policyPath, names: ['a'], backupDir: path.join(d, 'bk') });
    const before = load(policyPath);
    const r = ensurePolicy({ policyPath, names: ['a', 'b'], backupDir: path.join(d, 'bk') });
    assert.equal(r.updated, true);
    assert.deepEqual(r.added, ['b']);
    const after = load(policyPath);
    assert.deepEqual(after.mcp.allowed_servers, ['a', 'b']);
    after.mcp.allowed_servers = before.mcp.allowed_servers;
    assert.deepEqual(after, before, 'only the allowed_servers list changed');
    assert.equal(fs.readdirSync(path.join(d, 'bk')).length, 1, 'previous policy backed up');
  } finally {
    cleanup(d);
  }
});

test('a hand-edited block-style list is never rewritten; the user is told what to add', () => {
  const d = tmp();
  try {
    const policyPath = path.join(d, 'policy.yaml');
    const text = 'mcp:\n  allowed_servers:\n    - a\n';
    fs.writeFileSync(policyPath, text);
    const r = ensurePolicy({ policyPath, names: ['a', 'b'], backupDir: path.join(d, 'bk') });
    assert.equal(r.updated, false);
    assert.match(r.notice, /by hand.*b/);
    assert.equal(fs.readFileSync(policyPath, 'utf8'), text);
  } finally {
    cleanup(d);
  }
});

test('an invalid-YAML policy is left untouched with a notice, never overwritten', () => {
  const d = tmp();
  try {
    const policyPath = path.join(d, 'policy.yaml');
    fs.writeFileSync(policyPath, 'mcp: [unclosed\n');
    const r = ensurePolicy({ policyPath, names: ['a'], backupDir: path.join(d, 'bk') });
    assert.match(r.notice, /not valid YAML/);
    assert.equal(fs.readFileSync(policyPath, 'utf8'), 'mcp: [unclosed\n');
  } finally {
    cleanup(d);
  }
});

test('server names with YAML-special characters survive the round trip exactly', () => {
  const d = tmp();
  try {
    const names = ['plain', 'has: colon', 'has # hash', 'quote"d', "it's", '- dash', '[bracket]'];
    const policyPath = path.join(d, 'policy.yaml');
    ensurePolicy({ policyPath, names, backupDir: path.join(d, 'bk') });
    assert.deepEqual(load(policyPath).mcp.allowed_servers, names);
  } finally {
    cleanup(d);
  }
});
