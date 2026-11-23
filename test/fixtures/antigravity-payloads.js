// Antigravity hook payloads in the exact shape the real App sent during the
// Phase 6 validation spike (field names, nesting, argument names), with the
// machine-specific values replaced. Not a test file itself.

export const WORKSPACE = 'C:\\work\\demo';
export const CONVERSATION = '11111111-2222-4333-8444-555555555555';

const base = (hookEventName, extra = {}) => ({
  artifactDirectoryPath: `C:\\Users\\dev\\.gemini\\antigravity\\brain\\${CONVERSATION}`,
  conversationId: CONVERSATION,
  cwd: WORKSPACE,
  hookEventName,
  lastUserInput: 'please do the thing (typed prompt; must never be logged)',
  modelName: 'claude-sonnet-5-5-medium',
  transcriptPath: `C:\\Users\\dev\\.gemini\\antigravity\\brain\\${CONVERSATION}\\.system_generated\\logs\\transcript_full.jsonl`,
  workspacePaths: [WORKSPACE],
  ...extra,
});

let step = 0;
export const preToolUse = (name, args) =>
  base('PreToolUse', { stepIdx: (step += 2), toolCall: { args, id: `toolu_${step}`, name } });

/**
 * The shape the Linux build of Antigravity sends (Phase 6.5), which matches the
 * published docs: no `hookEventName`, no `cwd`.
 */
export function linuxShape(payload) {
  const { hookEventName, cwd, ...rest } = payload;
  return { ...rest, workspacePaths: ['/home/dev/DemoFiles'] };
}

export const sessionStart = () => base('SessionStart');
export const stop = () =>
  base('Stop', { continuationActive: false, error: '', executionNum: 0, fullyIdle: true, terminationReason: 'NO_TOOL_CALL' });

// Real tool calls seen in the spike.
export const real = {
  readFile: (p = `${WORKSPACE}\\canary-read.txt`) => preToolUse('read_file', { Path: p }),
  writeFile: (p = `${WORKSPACE}\\notes.txt`, content = 'hello') => preToolUse('write_file', { Content: content, Path: p }),
  writeFileGemini: (p = `${WORKSPACE}\\notes.txt`) => preToolUse('write_file', { Content: 'hello', Overwrite: true, Path: p }),
  editFile: (p = `${WORKSPACE}\\notes.txt`) => preToolUse('edit_file', { Path: p, Replacement: 'goodbye', Target: 'hello' }),
  runCommand: (cmd = 'git --version', extra = {}) =>
    preToolUse('run_command', { CommandLine: cmd, WaitMsBeforeAsync: 5000, toolSummary: 'Run a command', ...extra }),
  callMcp: (args = { content: 'hello' }) =>
    preToolUse('call_mcp_tool', { Arguments: args, ServerName: 'burpsuite', ToolName: 'base64_encode' }),
  invokeSubagent: (prompt = 'Read notes.txt and report its first word.') =>
    preToolUse('invoke_subagent', { Prompt: prompt, Role: 'File Reader', TypeName: 'research' }),
  sendMessage: (msg = 'The first word is hello.') => preToolUse('send_message', { Message: msg }),
  searchWeb: (q = 'antigravity hooks') => preToolUse('search_web', { domain: 'antigravity.google', query: q }),
  searchMarketplace: () => preToolUse('search_marketplace', { kind: 'all', queries: ['burp'] }),
};
