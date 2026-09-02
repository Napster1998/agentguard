import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/**
 * Lists running processes as [{pid, name}]. Read-only OS-native commands
 * with fixed args only (never shell-interpolated), so there is no command
 * injection surface. Fails safe to an empty list rather than throwing —
 * discovery must never crash the scan.
 */
export async function listProcesses() {
  return process.platform === 'win32' ? listWindows() : listPosix();
}

async function listWindows() {
  try {
    const { stdout } = await execFileAsync('tasklist', ['/fo', 'csv', '/nh']);
    return stdout.split(/\r?\n/).filter(Boolean).map(parseTasklistLine).filter(Boolean);
  } catch {
    return [];
  }
}

function parseTasklistLine(line) {
  // tasklist /fo csv quotes each field: "name","pid","session","session#","mem"
  const fields = line.match(/"([^"]*)"/g);
  if (!fields || fields.length < 2) return null;
  const name = fields[0].replace(/"/g, '');
  const pid = Number(fields[1].replace(/"/g, ''));
  return Number.isNaN(pid) ? null : { pid, name };
}

async function listPosix() {
  try {
    const { stdout } = await execFileAsync('ps', ['-axo', 'pid,comm']);
    return stdout
      .split(/\r?\n/)
      .slice(1)
      .map((line) => {
        const match = line.trim().match(/^(\d+)\s+(.+)$/);
        return match ? { pid: Number(match[1]), name: match[2] } : null;
      })
      .filter(Boolean);
  } catch {
    return [];
  }
}
