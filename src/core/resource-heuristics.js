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

export function findSecretMatches(value) {
  return SECRET_PATTERNS.filter((p) => p.re.test(value));
}

export function findSuspiciousInstructionMatch(value) {
  return SUSPICIOUS_INSTRUCTION_PATTERNS.find((re) => re.test(value)) || null;
}
