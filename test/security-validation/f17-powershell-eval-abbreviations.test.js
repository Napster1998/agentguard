// F17 (MEDIUM, FIXED): found while building Phase 6.3 (Antigravity run_command
// runs PowerShell). The F2 interpreter-eval check matched PowerShell's
// inline-code flags EXACTLY (`-command`, `-c`). PowerShell accepts any
// unambiguous abbreviation, with "-" or "/": `-co`, `-comm`, `/Command` are
// -Command, and `-e`, `-enc`, `-EncodedCommand`, `-ec` pass the code as base64,
// invisible to every other check. Before the fix (proved against the previous
// commit) all of those were NOT flagged, so with powershell allowed,
// `powershell -enc <base64>` ran arbitrary code. Not reachable with the shipped
// default policy (powershell is not in shell.allowed), but a real hole in the
// F2 mitigation for any policy that allows it, and for agent policies where an
// unlisted command is only a WARN.
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { isInterpreterEvalAttempt } from '../../src/core/resource-heuristics.js';
import { runExec } from '../../src/adapters/shell/exec-wrapper.js';
import { applyDefaults } from '../../src/core/policy-engine.js';

test('F17 FIXED: every abbreviation of -Command / -EncodedCommand, with - or /, is an interpreter-eval attempt', () => {
  for (const flag of ['-Command', '-c', '-co', '-com', '-comm', '-comma', '-comman', '/Command', '/c', '-EncodedCommand', '-e', '-en', '-enc', '-enco', '-encodedc', '-ec', '-EC']) {
    for (const exe of ['powershell', 'pwsh', 'powershell.exe', 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe']) {
      assert.equal(isInterpreterEvalAttempt(exe, [flag, 'x']), true, `${exe} ${flag}`);
    }
  }
});

test('F17: ordinary PowerShell switches are not mistaken for inline code', () => {
  for (const flag of ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', '-ex', '-File', '-f', '-Version', '-NoLogo', '-cx', '-encx']) {
    assert.equal(isInterpreterEvalAttempt('powershell', [flag]), false, flag);
  }
});

test('F17 FIXED end to end: agentguard exec blocks powershell -enc even when powershell is allowed, and never starts it', async () => {
  const result = await runExec({
    policy: applyDefaults({ shell: { allowed: ['powershell', 'pwsh'] } }),
    command: 'powershell',
    args: ['-NoProfile', '-enc', 'ZQBjAGgAbwAgAGgAaQA='], // "echo hi"
  });
  assert.equal(result.executed, false);
  assert.equal(result.decision.rule, 'shell.block_interpreter_eval');
});

test('F17 RESIDUAL (stays open, the F2 class): a script FILE is not inline code', () => {
  assert.equal(isInterpreterEvalAttempt('powershell', ['-File', 'payload.ps1']), false);
});
