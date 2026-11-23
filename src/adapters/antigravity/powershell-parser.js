import { execFileSync } from 'node:child_process';

/**
 * Asks PowerShell's OWN parser how it would read a command line, without
 * running it: [System.Management.Automation.Language.Parser]::ParseInput.
 * Re-implementing PowerShell's syntax (script blocks, subexpressions, aliases,
 * parameter abbreviations, quoting) would mean guessing; the real parser is
 * exactly what will interpret the line, so its answer is authoritative.
 *
 * Safety of the call itself:
 *  - the PowerShell script below is a FIXED constant, sent as -EncodedCommand
 *    (base64 UTF-16LE), so no quoting of it can go wrong;
 *  - the untrusted command line travels only as DATA in an environment
 *    variable and is only ever handed to ParseInput, never to Invoke-*;
 *  - -NoProfile -NonInteractive, and a timeout.
 *
 * Measured at about 280-330 ms per call on Windows PowerShell 5.1 (Phase 6
 * probe), so it runs only for run_command.
 */

const SCRIPT = String.raw`
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$src = $env:AGENTGUARD_PS_LINE
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errors)
function Enc($e) {
  if ($null -eq $e) { return $null }
  if ($e -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return @{ k = 'lit'; v = $e.Value } }
  if ($e -is [System.Management.Automation.Language.ConstantExpressionAst]) { return @{ k = 'lit'; v = [string]$e.Value } }
  if ($e -is [System.Management.Automation.Language.CommandParameterAst]) { return @{ k = 'param'; n = $e.ParameterName; arg = (Enc $e.Argument) } }
  if ($e -is [System.Management.Automation.Language.ArrayLiteralAst]) { return @{ k = 'arr'; items = @($e.Elements | ForEach-Object { Enc $_ }) } }
  return @{ k = 'expr'; t = $e.GetType().Name; text = $e.Extent.Text }
}
$commands = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object {
  $first = $_.CommandElements[0]
  @{
    name = if ($first -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $first.Value } else { $null }
    firstText = $first.Extent.Text
    op = $_.InvocationOperator.ToString()
    elements = @($_.CommandElements | Select-Object -Skip 1 | ForEach-Object { Enc $_ })
    redirections = @($_.Redirections | ForEach-Object {
      if ($_ -is [System.Management.Automation.Language.FileRedirectionAst]) { @{ k = 'file'; append = $_.Append; target = (Enc $_.Location) } } else { @{ k = 'merge' } }
    })
  }
})
$methods = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true) | ForEach-Object { $_.Extent.Text })
# Redirections not attached to a command (e.g. 'x' > file, after an expression).
$otherRedirections = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FileRedirectionAst] -and -not ($n.Parent -is [System.Management.Automation.Language.CommandAst]) }, $true) | ForEach-Object { @{ append = $_.Append; target = (Enc $_.Location) } })
# A drive-qualified variable such as {C:\path} after a dollar sign reads (or, assigned, writes) a FILE with no command at all.
$driveVariables = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.IsDriveQualified -and ($n.VariablePath.DriveName -notin @('env', 'variable', 'function', 'alias')) }, $true) | ForEach-Object { $_.Extent.Text })
[pscustomobject]@{ errors = @($errors | ForEach-Object { $_.Message }); commands = $commands; methodCalls = $methods; otherRedirections = $otherRedirections; driveVariables = $driveVariables } | ConvertTo-Json -Depth 10 -Compress
`;

const ENCODED = Buffer.from(SCRIPT, 'utf16le').toString('base64');

// Windows limits one environment variable to 32,767 characters; agents' command
// lines are far shorter, and anything longer is refused rather than cut.
export const MAX_COMMAND_LINE = 8000;

/**
 * @returns {{ok: true, ast: {errors: string[], commands: object[], methodCalls: string[]}} | {ok: false, reason: string}}
 */
export function parsePowerShell(line, { timeoutMs = 6000, exe = 'powershell.exe' } = {}) {
  if (typeof line !== 'string' || line.trim() === '') return { ok: false, reason: 'an empty command line' };
  if (line.length > MAX_COMMAND_LINE) return { ok: false, reason: `a command line longer than ${MAX_COMMAND_LINE} characters` };
  let out;
  try {
    out = execFileSync(exe, ['-NoProfile', '-NonInteractive', '-NoLogo', '-EncodedCommand', ENCODED], {
      env: { ...process.env, AGENTGUARD_PS_LINE: line },
      encoding: 'utf8',
      timeout: timeoutMs,
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch (err) {
    return { ok: false, reason: `a command PowerShell's parser could not be asked about (${err.code || 'error'})` };
  }
  try {
    const ast = JSON.parse(out.replace(/^﻿/, '').trim());
    return {
      ok: true,
      ast: {
        errors: toArray(ast.errors),
        commands: toArray(ast.commands).map(normalizeCommand),
        methodCalls: toArray(ast.methodCalls),
        otherRedirections: toArray(ast.otherRedirections).map((r) => ({ ...r, target: normalizeElement(r.target) })),
        driveVariables: toArray(ast.driveVariables),
      },
    };
  } catch {
    return { ok: false, reason: 'a command PowerShell\'s parser gave no readable answer for' };
  }
}

// ConvertTo-Json (5.1) may collapse a one-element array into the element itself.
function toArray(v) {
  if (v === null || v === undefined) return [];
  return Array.isArray(v) ? v : [v];
}

function normalizeElement(e) {
  if (!e || typeof e !== 'object') return e;
  if (e.k === 'arr') return { ...e, items: toArray(e.items).map(normalizeElement) };
  if (e.k === 'param') return { ...e, arg: e.arg ? normalizeElement(e.arg) : null };
  return e;
}

function normalizeCommand(c) {
  return {
    name: typeof c.name === 'string' ? c.name : null,
    firstText: c.firstText,
    op: c.op,
    elements: toArray(c.elements).map(normalizeElement),
    redirections: toArray(c.redirections).map((r) => (r && r.target ? { ...r, target: normalizeElement(r.target) } : r)),
  };
}
