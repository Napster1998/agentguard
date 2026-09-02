import fs from 'node:fs';

/**
 * Writes one JSONL record per decision (for machine consumption / future
 * scanner or dashboard) and a human-readable mirror to stderr.
 *
 * stdout is reserved exclusively for MCP protocol bytes; writing logs there
 * would corrupt the JSON-RPC stream, so this never touches stdout.
 *
 * Uses a synchronous append per event, deliberately — an audit log needs to
 * actually be on disk before the process that wrote it can exit or another
 * process can read it. A buffered async WriteStream doesn't guarantee that
 * (short-lived processes like `agentguard exec` can exit before a buffered
 * write flushes), and log() is called at most once per tool call, not in a
 * hot loop, so the synchronous cost is negligible.
 */
export class AuditLogger {
  constructor({ logFile } = {}) {
    this.logFile = logFile || null;
  }

  log(event) {
    if (this.logFile) fs.appendFileSync(this.logFile, JSON.stringify(event) + '\n');
    this.#printHuman(event);
  }

  #printHuman(event) {
    const prefix = `[${event.decision}]`;
    process.stderr.write(`${prefix} MCP request received\n`);
    if (event.toolName) process.stderr.write(`${prefix} Tool: ${event.toolName}\n`);
    if (event.resource) process.stderr.write(`${prefix} Target: ${event.resource}\n`);
    process.stderr.write(`${prefix} Policy decision: ${event.decision}\n`);
    if (event.decision !== 'ALLOW' && event.reason) {
      process.stderr.write(`${prefix} Reason: ${event.reason}\n`);
    }
  }

  close() {
    // No-op: appendFileSync has no open handle to release. Kept so callers
    // don't need to change and a future non-file backend has somewhere to
    // put its own cleanup.
  }
}
