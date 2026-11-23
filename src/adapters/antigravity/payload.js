/**
 * Validates and parses the JSON an Antigravity hook receives on stdin.
 *
 * Shape verified in the Phase 6 validation spike (real Antigravity App,
 * Windows; Claude and Gemini models), which differs from the published docs:
 * every event carries `hookEventName`, `conversationId`, `cwd` (the workspace),
 * `workspacePaths`, `modelName`, `transcriptPath`, `artifactDirectoryPath` and
 * `lastUserInput`; PreToolUse adds `stepIdx` and `toolCall {name, args, id}`.
 *
 * Only what AgentGuard needs is returned. `lastUserInput` and the transcript
 * path are deliberately dropped: AgentGuard records actions, not prompts.
 */

export const MAX_PAYLOAD_BYTES = 1024 * 1024;

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/**
 * @returns {{ok: true, event: string, conversationId: string, toolCall: {name: string, args: object, id: string|null}|null,
 *            cwd: string|null, workspacePaths: string[], modelName: string|null, stepIdx: number|null}
 *          | {ok: false, reason: string, conversationId: string|null}}
 */
export function parseHookPayload(raw) {
  const fail = (reason, conversationId = null) => ({ ok: false, reason, conversationId });

  if (typeof raw !== 'string' || raw.trim() === '') return fail('the hook received no input');
  if (Buffer.byteLength(raw, 'utf8') > MAX_PAYLOAD_BYTES) return fail('the hook input is larger than 1 MiB');

  let p;
  try {
    p = JSON.parse(raw);
  } catch (err) {
    return fail(`the hook input is not valid JSON (${err.message})`);
  }
  if (!isPlainObject(p)) return fail('the hook input is not a JSON object');

  const conversationId = typeof p.conversationId === 'string' && p.conversationId ? p.conversationId : null;
  if (typeof p.hookEventName !== 'string' || !p.hookEventName) return fail('the hook input has no hookEventName', conversationId);
  if (!conversationId) return fail('the hook input has no conversationId');

  let toolCall = null;
  if (p.hookEventName === 'PreToolUse') {
    const tc = p.toolCall;
    if (!isPlainObject(tc) || typeof tc.name !== 'string' || tc.name === '') {
      return fail('a PreToolUse input has no tool name', conversationId);
    }
    if (tc.args !== undefined && !isPlainObject(tc.args)) return fail(`the arguments of ${tc.name} are not an object`, conversationId);
    toolCall = { name: tc.name, args: tc.args ?? {}, id: typeof tc.id === 'string' ? tc.id : null };
  }

  return {
    ok: true,
    event: p.hookEventName,
    conversationId,
    toolCall,
    cwd: typeof p.cwd === 'string' && p.cwd ? p.cwd : null,
    workspacePaths: Array.isArray(p.workspacePaths) ? p.workspacePaths.filter((w) => typeof w === 'string') : [],
    modelName: typeof p.modelName === 'string' ? p.modelName : null,
    stepIdx: Number.isInteger(p.stepIdx) ? p.stepIdx : null,
  };
}
