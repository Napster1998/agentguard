import fs from 'node:fs';

/**
 * Writes one JSONL record per decision (for machine consumption / future
 * scanner or dashboard) and a human-readable mirror to stderr.
 *
 * stdout is reserved exclusively for MCP protocol bytes; writing logs there
 * would corrupt the JSON-RPC stream, so this never touches stdout.
 */
export class AuditLogger {
  constructor({ logFile } = {}) {
    this.stream = logFile ? fs.createWriteStream(logFile, { flags: 'a' }) : null;
  }

  log(event) {
    if (this.stream) this.stream.write(JSON.stringify(event) + '\n');
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
    if (this.stream) this.stream.end();
  }
}
