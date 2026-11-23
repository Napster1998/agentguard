/**
 * Fixed facts about PowerShell commands that the run_command translator needs.
 * Data only; each list says why it exists. Keys are lowercase.
 */

/**
 * Windows PowerShell 5.1's built-in aliases (Get-Alias), for the commands that
 * matter to a policy. An alias IS the command it stands for: `rm` deletes like
 * Remove-Item, and `curl` in 5.1 is Invoke-WebRequest, not curl.exe.
 */
export const ALIASES = {
  ls: 'Get-ChildItem', dir: 'Get-ChildItem', gci: 'Get-ChildItem',
  cat: 'Get-Content', type: 'Get-Content', gc: 'Get-Content',
  rm: 'Remove-Item', del: 'Remove-Item', erase: 'Remove-Item', rd: 'Remove-Item', rmdir: 'Remove-Item', ri: 'Remove-Item',
  cp: 'Copy-Item', copy: 'Copy-Item', cpi: 'Copy-Item',
  mv: 'Move-Item', move: 'Move-Item', mi: 'Move-Item',
  ren: 'Rename-Item', rni: 'Rename-Item',
  ni: 'New-Item', md: 'New-Item', mkdir: 'New-Item',
  sc: 'Set-Content', ac: 'Add-Content', clc: 'Clear-Content',
  gi: 'Get-Item', ii: 'Invoke-Item',
  cd: 'Set-Location', chdir: 'Set-Location', sl: 'Set-Location',
  pushd: 'Push-Location', popd: 'Pop-Location', pwd: 'Get-Location', gl: 'Get-Location',
  sls: 'Select-String', select: 'Select-Object', where: 'Where-Object', '?': 'Where-Object',
  foreach: 'ForEach-Object', '%': 'ForEach-Object', sort: 'Sort-Object', measure: 'Measure-Object',
  ft: 'Format-Table', fl: 'Format-List', echo: 'Write-Output', write: 'Write-Output',
  iex: 'Invoke-Expression', icm: 'Invoke-Command',
  iwr: 'Invoke-WebRequest', curl: 'Invoke-WebRequest', wget: 'Invoke-WebRequest', irm: 'Invoke-RestMethod',
  start: 'Start-Process', saps: 'Start-Process', kill: 'Stop-Process', spps: 'Stop-Process',
};

/** The reverse: every alias of a command (so a policy entry `rm` still matches `Remove-Item`). */
export const ALIASES_OF = Object.entries(ALIASES).reduce((acc, [alias, cmd]) => {
  (acc[cmd.toLowerCase()] ||= []).push(alias);
  return acc;
}, {});

/** Commands that run code given to them as TEXT: their argument cannot be evaluated. */
export const CODE_AS_TEXT = new Set(['invoke-expression', 'add-type']);

/**
 * Cmdlets whose (non-parameter) arguments are file paths, so a positional word
 * like `credentials` is checked as a path too, not only path-shaped words.
 * WRITERS change files (checked as FILE_WRITE).
 */
export const FILE_CMDLETS = new Set([
  'get-content', 'set-content', 'add-content', 'clear-content', 'out-file',
  'get-childitem', 'get-item', 'new-item', 'remove-item', 'copy-item', 'move-item', 'rename-item',
  'set-location', 'push-location', 'select-string', 'test-path', 'invoke-item', 'resolve-path',
  'import-csv', 'export-csv', 'get-filehash', 'expand-archive', 'compress-archive', 'start-process',
]);
export const WRITERS = new Set([
  'set-content', 'add-content', 'clear-content', 'out-file', 'new-item', 'remove-item', 'copy-item',
  'move-item', 'rename-item', 'export-csv', 'expand-archive', 'compress-archive',
]);

/** Parameters of file cmdlets whose value is NOT a path (a search text, an encoding, a name filter...). */
export const NON_PATH_PARAMS = new Set([
  'pattern', 'value', 'encoding', 'filter', 'include', 'exclude', 'itemtype', 'erroraction', 'width', 'depth',
  'first', 'last', 'tail', 'totalcount', 'head', 'property', 'delimiter', 'argumentlist', 'verb', 'windowstyle',
]);

/**
 * Pipeline/formatting cmdlets that touch no file or network themselves, so a
 * computed argument (a script block, `$_.Name`, an expression) is fine there.
 * For any OTHER command a computed argument hides what it will act on (e.g.
 * `git diff --no-index NUL $HOME\.aws\credentials`), so it is not guessed at.
 */
export const COMPUTED_ARGS_OK = new Set([
  'where-object', 'foreach-object', 'select-object', 'sort-object', 'group-object', 'measure-object',
  'format-table', 'format-list', 'format-wide', 'out-string', 'out-null', 'write-output', 'write-host',
  'convertto-json', 'convertfrom-json',
]);

/** Set-Location-like commands: a literal target changes the folder later relative paths resolve against. */
export const CHANGES_DIRECTORY = new Set(['set-location', 'push-location']);

/** Native recursive searchers, and the flag that makes them recursive (null = always recursive). */
export const NATIVE_RECURSIVE = {
  findstr: (a) => a.some((x) => /^\/s$/i.test(x)),
  rg: () => true,
  grep: (a) => a.some((x) => x === '-r' || x === '-R' || x === '--recursive' || /^-[a-zA-Z]*[rR][a-zA-Z]*$/.test(x)),
};
