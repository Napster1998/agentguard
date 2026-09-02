import fs from 'node:fs';

const RULE = '─'.repeat(40);

function parseArgs(argv) {
  const opts = { logFile: null, sessionId: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--log') opts.logFile = argv[++i];
    else if (argv[i] === '--session') opts.sessionId = argv[++i];
  }
  return opts;
}

/** Reads the JSONL audit log — the audit log IS the event store in Phase 2,
 * see README "Event correlation". Malformed lines are skipped, never thrown. */
export function readEvents(logFile) {
  if (!fs.existsSync(logFile)) return [];
  return fs
    .readFileSync(logFile, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

/** Groups events by sessionId and renders "what did this agent do this
 * session" — the foundational correlation view (2G). */
export function formatEvents(events, { sessionId } = {}) {
  const filtered = sessionId ? events.filter((e) => e.sessionId === sessionId) : events;
  if (filtered.length === 0) return 'No events found.';

  const bySession = new Map();
  for (const e of filtered) {
    if (!bySession.has(e.sessionId)) bySession.set(e.sessionId, []);
    bySession.get(e.sessionId).push(e);
  }

  const lines = [];
  for (const [sid, sessionEvents] of bySession) {
    sessionEvents.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    lines.push(`Session ${sid}`);
    lines.push(RULE);
    for (const e of sessionEvents) {
      lines.push(`[${e.decision}] ${e.timestamp}  ${e.toolName || e.method || ''}  ${e.resource || ''} (risk: ${e.risk})`);
      if (e.decision !== 'ALLOW') lines.push(`  reason: ${e.reason}`);
    }
    lines.push('');
  }
  return lines.join('\n').trimEnd();
}

export function runEventsCommand(argv) {
  const opts = parseArgs(argv);
  if (!opts.logFile) {
    process.stderr.write('Usage: agentguard events --log <file> [--session <id>]\n');
    process.exit(2);
  }
  const events = readEvents(opts.logFile);
  process.stdout.write(formatEvents(events, opts) + '\n');
}
