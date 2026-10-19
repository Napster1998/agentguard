import fs from 'node:fs';
import { correlate } from '../core/correlation-engine.js';
import { colorDecision, colorRisk, bold } from '../core/colors.js';
import { homePaths } from '../core/agentguard-home.js';

const RULE = '─'.repeat(40);
const DECISION_WIDTH = 6;
const RISK_WIDTH = 9;

function formatTime(ts) {
  const m = /T(\d{2}:\d{2}:\d{2})/.exec(ts || '');
  return m ? m[1] : '--:--:--';
}

/** Colors `text`, padding to `width` using the PLAIN length — padding an
 * already-colored string would count invisible ANSI bytes as visual width. */
function padColor(text, width, colorFn) {
  const plain = text || '';
  return colorFn(plain) + ' '.repeat(Math.max(1, width - plain.length));
}

function parseArgs(argv) {
  const opts = { logFile: null, sessionId: null, risk: null, blockedOnly: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--log') opts.logFile = argv[++i];
    else if (argv[i] === '--session') opts.sessionId = argv[++i];
    else if (argv[i] === '--risk') opts.risk = (argv[++i] || '').toUpperCase();
    else if (argv[i] === '--blocked') opts.blockedOnly = true;
  }
  return opts;
}

/** Reads the JSONL audit log — the audit log IS the event store, see
 * README "Event correlation". A malformed line (invalid JSON) is skipped,
 * never thrown; a valid-JSON event missing required fields (e.g. a
 * hand-edited or corrupted line lacking `timestamp`) is normalized rather
 * than left to crash a later `.timestamp.localeCompare()` — one bad line
 * must not take down the report for every other session in the file. */
export function readEvents(logFile) {
  if (!fs.existsSync(logFile)) return [];
  return fs
    .readFileSync(logFile, 'utf8')
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => {
      try {
        const parsed = JSON.parse(line);
        return typeof parsed === 'object' && parsed !== null ? { timestamp: '', ...parsed } : null;
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

/**
 * Groups events by sessionId, prints "what did this agent do this session"
 * (optionally filtered by --risk/--blocked for display), and runs the
 * correlation engine against each session's FULL event list — filtering
 * only affects what's *displayed*, never what's fed to correlate(), since
 * e.g. --blocked would otherwise hide the earlier WARN/ALLOW steps a
 * detected pattern depends on.
 */
export function formatEvents(events, { sessionId, risk, blockedOnly } = {}) {
  const scoped = sessionId ? events.filter((e) => e.sessionId === sessionId) : events;
  if (scoped.length === 0) return 'No events found.';

  const bySession = new Map();
  for (const e of scoped) {
    if (!bySession.has(e.sessionId)) bySession.set(e.sessionId, []);
    bySession.get(e.sessionId).push(e);
  }

  const lines = [];
  for (const [sid, sessionEvents] of bySession) {
    // Defensive: formatEvents() can be called directly (not just via
    // readEvents(), which normalizes this) - never let a missing
    // `timestamp` crash the whole report over one bad line.
    sessionEvents.sort((a, b) => (a.timestamp || '').localeCompare(b.timestamp || ''));

    const displayed = sessionEvents.filter((e) => {
      if (blockedOnly && e.decision !== 'BLOCK') return false;
      if (risk && e.risk !== risk) return false;
      return true;
    });

    const detections = correlate(sessionEvents, sid);
    if (displayed.length === 0 && detections.length === 0) continue;

    lines.push(bold(`Session ${sid}`));
    lines.push(RULE);
    for (const e of displayed) {
      const time = formatTime(e.timestamp);
      const decision = padColor(e.decision, DECISION_WIDTH, colorDecision);
      const risk = padColor(e.risk, RISK_WIDTH, colorRisk);
      const label = e.toolName || e.method || '';
      lines.push(`${time}  ${decision}${risk}${label}  ${e.resource || ''}`.trimEnd());
      if (e.decision !== 'ALLOW') lines.push(`  reason: ${e.reason}`);
    }

    for (const d of detections) {
      const agentIds = [...new Set(sessionEvents.map((e) => e.agentId).filter(Boolean))];
      lines.push('');
      lines.push(bold(`Detection: ${d.title}`));
      lines.push(`Severity: ${colorRisk(d.severity)}`);
      lines.push(`Session: ${sid}`);
      lines.push(`Agent: ${agentIds.join(', ') || 'unknown'}`);
      lines.push(d.description);
      lines.push(`Recommendation: ${d.recommendation}`);
    }

    lines.push('');
  }

  return lines.length === 0 ? 'No events found.' : lines.join('\n').trimEnd();
}

export function runEventsCommand(argv) {
  const opts = parseArgs(argv);
  // No --log: read the shared audit log that `agentguard wrap` points every
  // wrapped server at (~/.agentguard/audit.jsonl, or $AGENTGUARD_HOME).
  if (!opts.logFile) opts.logFile = homePaths().audit;
  const events = readEvents(opts.logFile);
  process.stdout.write(formatEvents(events, opts) + '\n');
}
