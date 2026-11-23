/**
 * A deliberately strict parser for a shell command LINE (one string), used
 * where an agent hands AgentGuard a command as text rather than as argv (an
 * MCP shell-style tool today; Antigravity's run_command later). See
 * SECURITY-ASSESSMENT.md F16: judging such a string by its first word let
 * `git status && rm -rf ~` through.
 *
 * The rule: accept only syntax that POSIX sh, PowerShell and cmd.exe would all
 * read the same way, because AgentGuard does not know which shell will run the
 * line. Everything else is REFUSED, never guessed; the caller turns a refusal
 * into a policy decision (shell.block_unparseable_commands, BLOCK by default).
 *
 * Accepted:
 *   - words made of letters, digits and  _ - . / : = + ~  (and "@" inside a word)
 *   - a whole word in 'single quotes' (no & | < > ^ % " ! inside: cmd.exe does
 *     not treat single quotes as quotes, so those would be live there)
 *   - a whole word in "double quotes" (no $ ` % ! inside, and no backslash
 *     before \ " $ ` : those expand or escape in at least one shell)
 *   - separators && || ; & |   (every command they separate is returned, so
 *     each one is evaluated; treating all of them as "runs the next command"
 *     over-approximates, which is the safe direction)
 *   - redirects > >> < with a plain target, optionally fd-prefixed (2>), and
 *     the fd duplications 2>&1 / 1>&2 / >&2
 *
 * Refused (non-exhaustive): $ and backticks (substitution, variables), globs,
 * ( ) { }, here-docs (<<), process substitution, a line break, a leading
 * VAR=value, a backslash outside quotes (an escape in POSIX shells but a path
 * separator on Windows, so the two readings differ), quotes that form only
 * part of a word, cmd.exe's % and ^, "!", "#", "," and a leading "@".
 *
 * This decides only how the line SPLITS. Whether each command is allowed is
 * still the policy engine's job, and what an allowed program then does with
 * its arguments is outside it (the F2 class).
 *
 * @returns {{ok: true, commands: Array<{argv: string[], redirects: Array<{op: string, target: string}>}>} | {ok: false, reason: string}}
 */
export function parseCommandLine(line) {
  if (typeof line !== 'string') return refuse('a command that is not text');

  const commands = [];
  let current = { argv: [], redirects: [] };
  let pendingRedirect = null;
  let lastSeparator = null;
  let i = 0;

  const isBoundary = (ch) => ch === undefined || ch === ' ' || ch === '\t' || ';&|<>'.includes(ch);

  function endCommand(separator) {
    if (pendingRedirect) return 'a redirection with no target';
    if (current.argv.length === 0 && current.redirects.length > 0) return 'a redirection with no command';
    if (current.argv.length === 0) return `"${separator}" with no command before it`;
    commands.push(current);
    current = { argv: [], redirects: [] };
    lastSeparator = separator;
    return null;
  }

  function pushWord(word, quoted) {
    if (pendingRedirect) {
      current.redirects.push({ op: pendingRedirect, target: word });
      pendingRedirect = null;
      return null;
    }
    if (!quoted && current.argv.length === 0 && /^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) {
      return 'an environment-variable assignment before the command';
    }
    current.argv.push(word);
    return null;
  }

  while (i < line.length) {
    const c = line[i];
    if (c === ' ' || c === '\t') {
      i++;
      continue;
    }
    if (c === '\n' || c === '\r') return refuse('a line break (more than one line)');

    const rest = line.slice(i);
    const sep = rest.startsWith('&&') ? '&&' : rest.startsWith('||') ? '||' : ';&|'.includes(c) ? c : null;
    if (sep) {
      // fd duplication like 2>&1 is handled below, before a bare "&" is seen.
      const err = endCommand(sep);
      if (err) return refuse(err);
      i += sep.length;
      continue;
    }

    const dup = /^[12]?>&[12]/.exec(rest);
    if (dup && isBoundary(rest[dup[0].length])) {
      if (pendingRedirect) return refuse('a redirection with no target');
      i += dup[0].length;
      continue;
    }
    const redirect = /^[12]?(>>|>|<)/.exec(rest);
    if (redirect) {
      const next = rest[redirect[0].length];
      if (next !== undefined && '<>&(|'.includes(next)) return refuse(`the redirection "${redirect[0]}${next}"`);
      if (pendingRedirect) return refuse('a redirection with no target');
      pendingRedirect = redirect[1];
      i += redirect[0].length;
      continue;
    }

    if (c === "'" || c === '"') {
      const close = line.indexOf(c, i + 1);
      if (close === -1) return refuse('an unterminated quote');
      const content = line.slice(i + 1, close);
      const bad = c === "'" ? quotedSingleProblem(content) : quotedDoubleProblem(content);
      if (bad) return refuse(bad);
      if (!isBoundary(line[close + 1])) return refuse('quotes that are only part of a word');
      const err = pushWord(content, true);
      if (err) return refuse(err);
      i = close + 1;
      continue;
    }

    let j = i;
    while (j < line.length && !isBoundary(line[j]) && line[j] !== '\n' && line[j] !== '\r') {
      const problem = unquotedCharProblem(line[j], j === i);
      if (problem) return refuse(problem);
      j++;
    }
    const err = pushWord(line.slice(i, j), false);
    if (err) return refuse(err);
    i = j;
  }

  if (pendingRedirect) return refuse('a redirection with no target');
  // "git log &> out" splits as "git log", "&", "> out": a redirect left over
  // with no command of its own would otherwise be silently dropped.
  if (current.argv.length === 0 && current.redirects.length > 0) return refuse('a redirection with no command');
  if (current.argv.length > 0) {
    commands.push(current);
  } else if (commands.length === 0) {
    return refuse('an empty command line');
  } else if (lastSeparator !== ';' && lastSeparator !== '&') {
    return refuse(`a command line that ends with "${lastSeparator}"`);
  }
  return { ok: true, commands };
}

function refuse(reason) {
  return { ok: false, reason };
}

const WORD_CHAR_RE = /[\p{L}\p{N}_\-./:=+~@]/u;

const CHAR_PROBLEMS = {
  $: 'a "$" (variable or command substitution)',
  '`': 'a backtick (command substitution, or an escape in PowerShell)',
  '(': 'parentheses (a subshell or grouping)',
  ')': 'parentheses (a subshell or grouping)',
  '{': 'braces (grouping or expansion)',
  '}': 'braces (grouping or expansion)',
  '*': 'a wildcard pattern',
  '?': 'a wildcard pattern',
  '[': 'a wildcard pattern',
  ']': 'a wildcard pattern',
  '%': 'a "%" (a cmd.exe variable)',
  '^': 'a "^" (the cmd.exe escape character)',
  '!': 'a "!" (history or delayed expansion)',
  '#': 'a "#" (a comment)',
  ',': 'a "," (a PowerShell array)',
  '\\': 'a backslash outside quotes (an escape in POSIX shells, a path separator on Windows; quote the word)',
  "'": 'quotes that are only part of a word',
  '"': 'quotes that are only part of a word',
};

function unquotedCharProblem(ch, atWordStart) {
  if (ch === '@' && atWordStart) return 'a "@" at the start of a word (PowerShell splatting)';
  if (WORD_CHAR_RE.test(ch)) return null;
  return CHAR_PROBLEMS[ch] || `the character "${ch}"`;
}

function quotedSingleProblem(content) {
  const bad = [...content].find((ch) => '&|<>^%"!\n\r'.includes(ch));
  return bad ? `"${bad === '\n' || bad === '\r' ? 'a line break' : bad}" inside single quotes (cmd.exe does not treat single quotes as quotes)` : null;
}

function quotedDoubleProblem(content) {
  for (let k = 0; k < content.length; k++) {
    const ch = content[k];
    if (ch === '\n' || ch === '\r') return 'a line break inside double quotes';
    if ('$`%!'.includes(ch)) return `"${ch}" inside double quotes (it expands there in at least one shell)`;
    if (ch === '\\' && (k === content.length - 1 || '\\"$`'.includes(content[k + 1]))) {
      return 'a backslash escape inside double quotes';
    }
  }
  return null;
}
