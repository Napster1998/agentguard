import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { readConfigFile, serializeConfig, writeConfigSafely, serverTable, ConfigError } from '../src/adapters/wrap/config-file.js';

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'ag-cfg-'));
}
const cleanup = (d) => fs.rmSync(d, { recursive: true, force: true });
const obj = { mcpServers: { a: { command: 'x', args: ['1'] } }, other: { keep: true } };

test('serialize(read(file)) is byte-identical for every common formatting', () => {
  const dir = tmp();
  try {
    const variants = [
      JSON.stringify(obj, null, 2) + '\n',
      JSON.stringify(obj, null, 2),
      JSON.stringify(obj, null, 4) + '\n',
      JSON.stringify(obj, null, '\t') + '\n',
      JSON.stringify(obj, null, 2).replace(/\n/g, '\r\n') + '\r\n',
      '﻿' + JSON.stringify(obj, null, 2) + '\n',
    ];
    variants.forEach((text, i) => {
      const f = path.join(dir, `c${i}.json`);
      fs.writeFileSync(f, text);
      assert.equal(serializeConfig(readConfigFile(f)), text, `variant ${i}`);
    });
  } finally {
    cleanup(dir);
  }
});

test('an empty file is "no servers yet", not an error', () => {
  const dir = tmp();
  try {
    const f = path.join(dir, 'empty.json');
    fs.writeFileSync(f, '');
    const info = readConfigFile(f);
    assert.deepEqual(serverTable(info), {});
  } finally {
    cleanup(dir);
  }
});

test('unparseable, non-object, and absent files raise a typed ConfigError and are never modified', () => {
  const dir = tmp();
  try {
    const bad = path.join(dir, 'bad.json');
    fs.writeFileSync(bad, '{ nope');
    assert.throws(() => readConfigFile(bad), (e) => e instanceof ConfigError && e.kind === 'unparseable');
    assert.equal(fs.readFileSync(bad, 'utf8'), '{ nope');

    const arr = path.join(dir, 'arr.json');
    fs.writeFileSync(arr, '[1,2]');
    assert.throws(() => readConfigFile(arr), (e) => e.kind === 'not-an-object');

    assert.throws(() => readConfigFile(path.join(dir, 'missing.json')), (e) => e.kind === 'absent');
  } finally {
    cleanup(dir);
  }
});

test('writeConfigSafely backs up the exact original bytes, replaces atomically, leaves no temp file', () => {
  const dir = tmp();
  try {
    const f = path.join(dir, 'cfg.json');
    const original = JSON.stringify(obj, null, 2) + '\n';
    fs.writeFileSync(f, original);
    const info = readConfigFile(f);
    const next = { ...obj, mcpServers: { a: { command: 'changed' } } };
    const backup = writeConfigSafely(info, serializeConfig(info, next), { backupDir: path.join(dir, 'bk') });

    assert.equal(fs.readFileSync(backup, 'utf8'), original, 'backup is the exact previous content');
    assert.equal(JSON.parse(fs.readFileSync(f, 'utf8')).mcpServers.a.command, 'changed');
    assert.deepEqual(fs.readdirSync(dir).filter((n) => n.includes('agentguard-tmp')), []);
  } finally {
    cleanup(dir);
  }
});

test('writeConfigSafely refuses (and writes nothing) if the file changed after it was read', () => {
  const dir = tmp();
  try {
    const f = path.join(dir, 'cfg.json');
    fs.writeFileSync(f, JSON.stringify(obj));
    const info = readConfigFile(f);
    fs.writeFileSync(f, JSON.stringify({ mcpServers: { edited: { command: 'by-the-app' } } }));
    assert.throws(
      () => writeConfigSafely(info, serializeConfig(info), { backupDir: path.join(dir, 'bk') }),
      (e) => e.kind === 'changed'
    );
    assert.ok(JSON.parse(fs.readFileSync(f, 'utf8')).mcpServers.edited, "the app's concurrent edit survives");
    assert.equal(fs.existsSync(path.join(dir, 'bk')), false, 'no backup made for a refused write');
  } finally {
    cleanup(dir);
  }
});
