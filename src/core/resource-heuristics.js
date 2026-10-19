/**
 * Shared, best-effort heuristics for classifying free-form strings into
 * resource shapes (path / URL / secret / write-vs-read). Used by both the
 * MCP adapter (classifying JSON tool-call arguments) and the shell-exec
 * adapter (classifying real argv) so the two don't drift into inconsistent
 * judgment calls about what "looks like a path" means. Deliberately narrow
 * — see README "Limitations" for what this does and doesn't catch.
 */

export const PATH_KEY_RE = /path|file|dir|directory|target|cwd|location|filename/i;
export const URL_RE = /^[a-z][a-z0-9+.-]*:\/\//i;

// A key that ends in host/hostname/domain names a network destination
// (e.g. `host`, `targetHostname`, `target_host`). Checked BEFORE PATH_KEY_RE
// so a key like `targetHostname` (contains "target") isn't filed as a path.
// Matched at the END of the key so `host_file` / `hostsPath` stay paths.
export const NETWORK_KEY_RE = /(host|hostname|domain)$/i;

const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/i;
const HTTP_REQUEST_LINE_RE = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)[ \t]+(\S+)[ \t]+HTTP\/\d(\.\d)?\r?$/m;

// Best-effort only: we don't know each server's/command's exact semantics,
// so a name is the only signal available for read vs write. Defaults to
// read (far more common) rather than over-claiming.
export const WRITE_TOOL_RE = /write|create|append|delete|remove|unlink|rm|update|edit|save|rename|move|mkdir/i;

// Deliberately narrow, high-confidence patterns. This is a heuristic scan,
// not a general-purpose DLP engine (see README limitations).
export const SECRET_PATTERNS = [
  { name: 'aws-access-key-id', re: /AKIA[0-9A-Z]{16}/ },
  { name: 'private-key-block', re: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/ },
  { name: 'generic-secret-assignment', re: /(api[_-]?key|secret|token)["']?\s*[:=]\s*["'][A-Za-z0-9/+_-]{20,}["']/i },
];

// Rough, deliberately narrow patterns for instruction-injection-shaped text
// in an MCP tool-call *response*. This is pattern-matching, not comprehension
// — a detection signal to surface, never proof of an actual attack.
export const SUSPICIOUS_INSTRUCTION_PATTERNS = [
  /ignore (all |the )?previous instructions/i,
  /disregard (all |your |the )?(previous |prior )?instructions/i,
  /you (must|should) now/i,
  /new instructions?:/i,
  /system\s*:\s*you are/i,
];

export function looksLikePath(value) {
  if (typeof value !== 'string' || value.length === 0) return false;
  if (value.startsWith('~')) return true;
  if (/^[a-zA-Z]:[\\/]/.test(value)) return true; // C:\ or C:/
  if (value.startsWith('/') || value.startsWith('./') || value.startsWith('../')) return true;
  if (value.includes('/') || value.includes('\\')) return true;
  return false;
}

export function extractHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Parses a bare hostname (optionally with a `:port` suffix) out of a value
 * found under a host-style key. Returns the lowercased hostname, or null if
 * the value isn't plausibly a hostname/IPv4 (anything with a slash, spaces,
 * etc.), so callers can fall through to the existing classification.
 * Deliberately narrow: bracketed IPv6 is not handled.
 */
export function parseBareHostname(value) {
  if (typeof value !== 'string') return null;
  const host = value.trim().replace(/:\d{1,5}$/, '');
  return HOSTNAME_RE.test(host) ? host.toLowerCase() : null;
}

/**
 * Recognizes raw HTTP/1.x request text (e.g. Burp's `content` argument) and
 * returns the destination hosts it names: its `Host:` header and/or an
 * absolute-form request target. Returns null when the value is not an HTTP
 * request at all, so it isn't mistaken for one. An HTTP request with no
 * recoverable host returns `{ hosts: [] }`.
 *
 * @returns {{hosts: string[]}|null}
 */
export function parseRawHttpRequest(value) {
  if (typeof value !== 'string') return null;
  const requestLine = value.match(HTTP_REQUEST_LINE_RE);
  if (!requestLine || requestLine.index !== 0) return null;

  const hosts = [];
  if (URL_RE.test(requestLine[2])) {
    const fromTarget = extractHostname(requestLine[2]);
    if (fromTarget) hosts.push(fromTarget.toLowerCase());
  }
  const hostHeader = value.match(/^host:[ \t]*([^\r\n]+)/im);
  const fromHeader = hostHeader ? parseBareHostname(hostHeader[1]) : null;
  if (fromHeader && !hosts.includes(fromHeader)) hosts.push(fromHeader);
  return { hosts };
}

export function findSecretMatches(value) {
  return SECRET_PATTERNS.filter((p) => p.re.test(value));
}

export function findSuspiciousInstructionMatch(value) {
  return SUSPICIOUS_INSTRUCTION_PATTERNS.find((re) => re.test(value)) || null;
}

/**
 * shell.allowed only ever inspects the top-level binary — it has no
 * visibility into what a general-purpose interpreter is INSTRUCTED to do.
 * `node -e "<anything>"` runs arbitrary code, and "node" being allowed
 * gives that code the same trust as any other allowed command. This is a
 * narrow, deliberately incomplete mitigation for the single most blatant
 * case (a well-known interpreter + its inline-eval flag) — see
 * SECURITY-ASSESSMENT.md F2. It does NOT catch: writing a script to a file
 * and running that, `require()`/`import()` tricks, or any interpreter not
 * in this small table. Treat this as raising the bar, not closing the gap.
 */
const INTERPRETER_EVAL_FLAGS = {
  node: ['-e', '--eval'],
  nodejs: ['-e', '--eval'],
  python: ['-c'],
  python3: ['-c'],
  ruby: ['-e'],
  perl: ['-e'],
  sh: ['-c'],
  bash: ['-c'],
  zsh: ['-c'],
  ksh: ['-c'],
  cmd: ['/c', '/k'],
  powershell: ['-command', '-c'],
  pwsh: ['-command', '-c'],
};

function normalizeInterpreterName(binary) {
  return binary
    .replace(/\\/g, '/')
    .split('/')
    .pop()
    .toLowerCase()
    .replace(/\.(exe|cmd|bat|com|ps1)$/i, '');
}

/** @param {string} binary  @param {string[]} args */
export function isInterpreterEvalAttempt(binary, args) {
  const flags = INTERPRETER_EVAL_FLAGS[normalizeInterpreterName(binary)];
  if (!flags) return false;
  return args.some((a) => typeof a === 'string' && flags.includes(a.toLowerCase()));
}
