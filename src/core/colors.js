/**
 * Minimal ANSI coloring for ALLOW/WARN/BLOCK and risk levels — readable on
 * a projected terminal, and never load-bearing: every caller keeps the
 * plain bracketed text label ("[BLOCK]", "CRITICAL", ...) as the actual
 * signal, so meaning survives with color stripped entirely. Auto-disables
 * when not attached to a real terminal (piped output, CI, tests spawning
 * this as a child process) or when NO_COLOR is set, per the NO_COLOR
 * convention — so nothing here can leak escape codes into a log file or
 * break a test asserting on exact text.
 */

const CODES = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
};

function enabled(stream) {
  return Boolean(stream && stream.isTTY) && !process.env.NO_COLOR;
}

function wrap(stream, code, text) {
  return enabled(stream) ? `${code}${text}${CODES.reset}` : text;
}

export function colorDecision(decision, stream = process.stderr) {
  if (decision === 'BLOCK') return wrap(stream, CODES.bold + CODES.red, decision);
  if (decision === 'WARN') return wrap(stream, CODES.bold + CODES.yellow, decision);
  if (decision === 'ALLOW') return wrap(stream, CODES.green, decision);
  return decision;
}

export function colorRisk(risk, stream = process.stderr) {
  if (risk === 'CRITICAL') return wrap(stream, CODES.bold + CODES.red, risk);
  if (risk === 'HIGH') return wrap(stream, CODES.red, risk);
  if (risk === 'MEDIUM') return wrap(stream, CODES.yellow, risk);
  if (risk === 'LOW') return wrap(stream, CODES.dim, risk);
  return risk;
}

export function colorSeverity(severity, stream = process.stdout) {
  return colorRisk(severity, stream);
}

export function bold(text, stream = process.stdout) {
  return wrap(stream, CODES.bold, text);
}
