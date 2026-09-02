import os from 'node:os';

function normalize(p) {
  return collapseDotSegments(p.replace(/\\/g, '/'));
}

/**
 * Lexically collapses `.` and `..` path segments (e.g.
 * "./workspace/../../etc/passwd" -> "../etc/passwd"), WITHOUT touching the
 * real filesystem — no symlink resolution, no existence check. This closes
 * the traversal bypass where a value lexically matched an allow/deny
 * pattern's prefix while actually resolving somewhere else entirely (see
 * README "Limitations" — this is still not full canonicalization).
 */
function collapseDotSegments(p) {
  const isAbsolute = p.startsWith('/');
  const parts = p.split('/');
  const out = [];
  for (const part of parts) {
    if (part === '.' || part === '') continue;
    if (part === '..') {
      const top = out[out.length - 1];
      // `~` is a fixed anchor (the home directory), not a poppable segment
      // like a real directory name — excess ".." past it clamps at the
      // anchor instead of discarding it (matching how ".." past a real
      // filesystem root clamps at root rather than going negative).
      if (out.length > 0 && top !== '..' && top !== '~') {
        out.pop();
      } else if (!isAbsolute && top !== '~') {
        out.push('..');
      }
      continue;
    }
    out.push(part);
  }
  const collapsed = out.join('/');
  const prefix = isAbsolute ? '/' : '';
  // Preserve a leading "./" for a purely relative, non-traversing path so
  // "./workspace/**"-style patterns still line up visually with input like
  // "./workspace/x" (functionally harmless either way since matching is
  // prefix-based, but keeps evidence/log output readable).
  if (!isAbsolute && p.startsWith('./') && !collapsed.startsWith('..')) {
    return './' + collapsed;
  }
  return prefix + collapsed;
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
