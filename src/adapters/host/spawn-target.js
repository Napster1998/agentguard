import fs from 'node:fs';
import path from 'node:path';

/** Thrown when a command cannot be started safely; message is user-facing. */
export class SpawnRefusal extends Error {}

// Characters cmd.exe would interpret (command chaining, redirection, variable
// expansion) or that break its quoting. An argument containing one is refused
// rather than escaped: escaping for cmd.exe is subtle, and refusing fails
// closed with a clear message.
const CMD_META = /[&|<>^%"\r\n]/;
const SEARCH_EXTS = ['.exe', '.com', '.cmd', '.bat'];
const SHIM_EXTS = new Set(['.cmd', '.bat']);

/**
 * Works out how to launch the downstream MCP server on this platform.
 *
 * On Windows, many real MCP servers are launched as `npx ...`, which is a
 * `.cmd` shim. Node's spawn() without a shell cannot start one: a bare `npx`
 * fails with ENOENT and `npx.cmd` is rejected with EINVAL (the fix for
 * CVE-2024-27980). Those commands must go through `cmd.exe /d /s /c`, which
 * is exactly how MCP clients launch them. Everything else (real executables,
 * non-Windows platforms) is passed through unchanged, and a command that
 * cannot be found is also passed through so spawn() reports it honestly.
 *
 * The values come from the operator's own config, not from an agent, but they
 * are still validated: see CMD_META.
 *
 * @returns {{command:string, args:string[]}}
 * @throws {SpawnRefusal}
 */
export function resolveSpawnTarget(command, args = [], { platform = process.platform, env = process.env, exists = fs.existsSync } = {}) {
  if (platform !== 'win32') return { command, args };

  const ext = path.extname(command).toLowerCase();
  if (ext === '.exe' || ext === '.com') return { command, args };

  const hasDir = /[\\/]/.test(command);
  const exts = ext ? [''] : SEARCH_EXTS;
  const dirs = hasDir ? [null] : String(env.PATH ?? env.Path ?? '').split(';').filter(Boolean);

  let hit = null;
  outer: for (const dir of dirs) {
    for (const e of exts) {
      const candidate = dir === null ? command + e : path.join(dir, command + e);
      if (exists(candidate)) {
        hit = candidate;
        break outer;
      }
    }
  }
  if (!hit || !SHIM_EXTS.has(path.extname(hit).toLowerCase())) return { command, args };

  if (/\s/.test(command)) {
    throw new SpawnRefusal(
      `"${command}" is a .cmd/.bat script whose path contains a space, which cannot be started safely through cmd.exe. ` +
        'Point the MCP server at a path without spaces, or at the underlying .exe.'
    );
  }
  const bad = args.findIndex((a) => CMD_META.test(a));
  if (bad !== -1 || CMD_META.test(command)) {
    throw new SpawnRefusal(
      `refusing to start "${command}" through cmd.exe: ${bad === -1 ? 'the command' : `argument ${bad + 1}`} contains a character cmd.exe would interpret ` +
        '(one of & | < > ^ % "). Use an .exe launcher, or remove the character.'
    );
  }

  return { command: env.ComSpec || 'cmd.exe', args: ['/d', '/s', '/c', command, ...args] };
}
