import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/**
 * Looks up ONE fixed binary name on PATH (`where`/`which`). This exists to
 * check a small known registry of binary names (see known-agents.js) — it
 * must never be called with a discovered or user-controlled string, since
 * that would be an execution-adjacent injection surface.
 */
export async function findOnPath(binaryName) {
  const cmd = process.platform === 'win32' ? 'where' : 'which';
  try {
    const { stdout } = await execFileAsync(cmd, [binaryName]);
    const first = stdout.split(/\r?\n/).find(Boolean);
    return first ? first.trim() : null;
  } catch {
    return null;
  }
}
