import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';

/** A config problem the user should be told about, never a crash. */
export class ConfigError extends Error {
  constructor(kind, message) {
    super(message);
    this.kind = kind; // 'absent' | 'unparseable' | 'not-an-object' | 'changed'
  }
}

const sha = (text) => crypto.createHash('sha256').update(text).digest('hex');

/**
 * Reads a JSON config file and remembers how it was formatted so a rewrite
 * changes as little as possible (indent, line endings, BOM, trailing
 * newline). An empty file is treated as `{}` (a freshly created, not-yet-
 * used config), not as an error.
 */
export function readConfigFile(file) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch (err) {
    throw new ConfigError('absent', `cannot read ${file}: ${err.code || err.message}`);
  }

  const bom = raw.startsWith('﻿') ? '﻿' : '';
  const text = bom ? raw.slice(1) : raw;
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const indentMatch = text.match(/^([ \t]+)"/m);

  let parsed;
  if (text.trim() === '') {
    parsed = {};
  } else {
    try {
      parsed = JSON.parse(text);
    } catch (err) {
      throw new ConfigError('unparseable', `not valid JSON (${err.message}); left untouched`);
    }
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new ConfigError('not-an-object', 'top level is not a JSON object; left untouched');
  }

  return {
    file,
    parsed,
    hash: sha(raw),
    format: { bom, eol, indent: indentMatch ? indentMatch[1] : '  ', finalNewline: /\n$/.test(text) },
  };
}

/** The config's server table, or {} if it has none. */
export function serverTable(info) {
  const t = info.parsed.mcpServers ?? info.parsed.mcp_servers;
  return t && typeof t === 'object' && !Array.isArray(t) ? t : {};
}

/** Which key holds the server table in this file (mcpServers is canonical). */
export function serverTableKey(info) {
  return info.parsed.mcp_servers && !info.parsed.mcpServers ? 'mcp_servers' : 'mcpServers';
}

export function serializeConfig(info, parsed = info.parsed) {
  const { bom, eol, indent, finalNewline } = info.format;
  let text = JSON.stringify(parsed, null, indent);
  if (eol === '\r\n') text = text.replace(/\n/g, '\r\n');
  return bom + text + (finalNewline ? eol : '');
}

/**
 * Backs up the file's exact current bytes, then replaces it atomically
 * (temp file in the same directory + rename). Refuses if the file changed
 * since `info` was read, so a concurrent edit by the app is never clobbered.
 *
 * @returns {string} path of the backup
 */
export function writeConfigSafely(info, newText, { backupDir, now = new Date() }) {
  const current = fs.readFileSync(info.file, 'utf8');
  if (sha(current) !== info.hash) {
    throw new ConfigError('changed', `${info.file} changed while planning; nothing was written (re-run)`);
  }

  fs.mkdirSync(backupDir, { recursive: true });
  const stamp = now.toISOString().replace(/[:.]/g, '-');
  const safeName = info.file.replace(/[^A-Za-z0-9._-]+/g, '_').slice(-80);
  const backup = path.join(backupDir, `${stamp}__${safeName}.bak`);
  fs.writeFileSync(backup, current);

  const tmp = `${info.file}.agentguard-tmp-${process.pid}`;
  try {
    fs.writeFileSync(tmp, newText);
    fs.renameSync(tmp, info.file);
  } catch (err) {
    try {
      fs.unlinkSync(tmp);
    } catch {
      /* temp may not exist */
    }
    throw err;
  }
  return backup;
}
