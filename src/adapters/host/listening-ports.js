import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

/**
 * Lists TCP listening sockets as [{host, port, pid}] using the local
 * machine's own socket table (netstat/lsof) — this is NOT a network
 * scanner, it never opens a connection to anything. Best-effort: on POSIX
 * this depends on `lsof` being installed, and degrades to an empty list
 * (not a throw) if it isn't — documented limitation, not a bug.
 */
export async function listListeningPorts() {
  return process.platform === 'win32' ? listWindows() : listPosix();
}

async function listWindows() {
  try {
    const { stdout } = await execFileAsync('netstat', ['-ano', '-p', 'TCP']);
    const results = [];
    for (const line of stdout.split(/\r?\n/)) {
      const match = line.trim().match(/^TCP\s+(\S+)\s+\S+\s+LISTENING\s+(\d+)/i);
      if (!match) continue;
      const [, localAddr, pidStr] = match;
      const lastColon = localAddr.lastIndexOf(':');
      if (lastColon === -1) continue;
      results.push({
        host: localAddr.slice(0, lastColon),
        port: Number(localAddr.slice(lastColon + 1)),
        pid: Number(pidStr),
      });
    }
    return results;
  } catch {
    return [];
  }
}

async function listPosix() {
  try {
    const { stdout } = await execFileAsync('lsof', ['-iTCP', '-sTCP:LISTEN', '-P', '-n']);
    const results = [];
    for (const line of stdout.split(/\r?\n/).slice(1)) {
      const trimmed = line.trim();
      const match = trimmed.match(/(\S+):(\d+)\s*\(LISTEN\)\s*$/);
      if (!match) continue;
      const pidField = trimmed.split(/\s+/)[1];
      results.push({ host: match[1], port: Number(match[2]), pid: Number(pidField) });
    }
    return results;
  } catch {
    return [];
  }
}
