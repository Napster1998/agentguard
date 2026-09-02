import os from 'node:os';

function normalize(p) {
  return p.replace(/\\/g, '/');
}

/** Converts a restricted glob subset (`*`, `**`, literal chars) to a regex source. */
function toRegexSource(glob) {
  let out = '';
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === '*' && glob[i + 1] === '*') {
      out += '.*';
      i++;
      if (glob[i + 1] === '/') i++;
    } else if (c === '*') {
      out += '[^/]*';
    } else if (c === '?') {
      out += '[^/]';
    } else if ('.+^${}()|[]\\'.includes(c)) {
      out += '\\' + c;
    } else {
      out += c;
    }
  }
  return out;
}

/** A leading `~` also gets a variant expanded against the real home dir, so a
 * pattern written as `~/.ssh/**` matches both a literal `~/.ssh/...` string
 * and the absolute path an MCP server would typically report. */
function expandedVariants(p) {
  const norm = normalize(p);
  const variants = new Set([norm]);
  if (norm === '~' || norm.startsWith('~/')) {
    variants.add(normalize(os.homedir()) + norm.slice(1));
  }
  return [...variants];
}

/**
 * Returns the first pattern in `patterns` that matches `value`, or null.
 * Matching is case-insensitive by design: for a deny/warn list this is the
 * safer direction (it catches more, never fewer, potential matches).
 */
export function matchesAny(value, patterns = []) {
  if (typeof value !== 'string' || value.length === 0) return null;
  const valueVariants = expandedVariants(value);
  for (const pattern of patterns) {
    const regexes = expandedVariants(pattern).map(
      (v) => new RegExp('^' + toRegexSource(v) + '$', 'i')
    );
    if (valueVariants.some((v) => regexes.some((re) => re.test(v)))) {
      return pattern;
    }
  }
  return null;
}
