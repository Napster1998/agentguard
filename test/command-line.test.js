import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCommandLine } from '../src/core/command-line.js';

const argvs = (line) => {
  const r = parseCommandLine(line);
  assert.equal(r.ok, true, `${JSON.stringify(line)} should parse, got: ${r.reason}`);
  return r.commands.map((c) => c.argv);
};

test('plain words and whole-word quotes split into argv', () => {
  assert.deepEqual(argvs('git status'), [['git', 'status']]);
  assert.deepEqual(argvs('  git   log\t--oneline  '), [['git', 'log', '--oneline']]);
  assert.deepEqual(argvs('git commit -m "fix: a & b | c; d"'), [['git', 'commit', '-m', 'fix: a & b | c; d']]);
  assert.deepEqual(argvs("git commit -m 'it works'"), [['git', 'commit', '-m', 'it works']]);
  assert.deepEqual(argvs('git -C "C:\\Program Files\\repo" status'), [['git', '-C', 'C:\\Program Files\\repo', 'status']]);
  assert.deepEqual(argvs('npm install left-pad@1.3.0 ~/x.txt --save=true'), [['npm', 'install', 'left-pad@1.3.0', '~/x.txt', '--save=true']]);
  assert.deepEqual(argvs('"C:/tools/git.exe" status'), [['C:/tools/git.exe', 'status']]);
});

test('every separator yields its own command; trailing ; and & are allowed', () => {
  assert.deepEqual(argvs('a && b || c ; d & e | f'), [['a'], ['b'], ['c'], ['d'], ['e'], ['f']]);
  assert.deepEqual(argvs('a;b&&c'), [['a'], ['b'], ['c']]);
  assert.deepEqual(argvs('npm start &'), [['npm', 'start']]);
  assert.deepEqual(argvs('git status;'), [['git', 'status']]);
});

test('redirects are captured with their target; fd duplication is not a file', () => {
  const r = parseCommandLine('git log > out.txt 2>> err.log < in.txt 2>&1');
  assert.equal(r.ok, true);
  assert.deepEqual(r.commands[0].argv, ['git', 'log']);
  assert.deepEqual(r.commands[0].redirects, [
    { op: '>', target: 'out.txt' },
    { op: '>>', target: 'err.log' },
    { op: '<', target: 'in.txt' },
  ]);
  const before = parseCommandLine('> out.txt git log');
  assert.deepEqual(before.commands[0], { argv: ['git', 'log'], redirects: [{ op: '>', target: 'out.txt' }] });
  assert.deepEqual(parseCommandLine('git log >&2').commands[0].redirects, []);
});

test('anything outside the shared grammar is refused, with a reason a person can read', () => {
  const refusals = [
    ['echo $HOME', '"$"'],
    ['echo `id`', 'backtick'],
    ['git log $(whoami)', '"$"'],
    ['ls *.js', 'wildcard'],
    ['ls file?.txt', 'wildcard'],
    ['(cd x)', 'parentheses'],
    ['{ a; }', 'braces'],
    ['cat <<EOF', 'redirection "<<"'],
    ['diff <(a) b', 'redirection "<("'],
    ['git log >| x', 'redirection ">|"'],
    ['a\nb', 'line break'],
    ['a\r\nb', 'line break'],
    ['FOO=1 git log', 'environment-variable'],
    ['git log C:\\repo', 'backslash outside quotes'],
    ['git log ab"cd"', 'only part of a word'],
    ['git log "ab"cd', 'only part of a word'],
    ['git log "unterminated', 'unterminated'],
    ['git log "$HOME"', '"$" inside double quotes'],
    ['git log "a\\"b"', 'backslash escape'],
    ['git log "C:\\dir\\"', 'backslash escape'],
    ["git log 'a & b'", 'inside single quotes'],
    ['git log %PATH%', 'cmd.exe variable'],
    ['git log ^& x', 'cmd.exe escape'],
    ['git log !1', '"!"'],
    ['git log # comment', 'comment'],
    ['git log a,b', 'PowerShell array'],
    ['npm i @scope/pkg', 'splatting'],
    ['git log > ', 'no target'],
    ['git log > && x', 'no target'],
    ['git log &> out', 'redirection with no command'],
    ['&& git log', 'with no command before it'],
    ['git log | | x', 'with no command before it'],
    ['git log &&', 'ends with "&&"'],
    ['git log |', 'ends with "|"'],
    ['', 'empty'],
    ['   ', 'empty'],
    ['git log “smart”', 'the character'],
  ];
  for (const [line, fragment] of refusals) {
    const r = parseCommandLine(line);
    assert.equal(r.ok, false, `${JSON.stringify(line)} must be refused`);
    assert.ok(r.reason.includes(fragment), `${JSON.stringify(line)}: reason "${r.reason}" should mention ${fragment}`);
  }
});

test('a non-string is refused rather than throwing', () => {
  for (const v of [undefined, null, 42, {}, []]) assert.equal(parseCommandLine(v).ok, false);
});
