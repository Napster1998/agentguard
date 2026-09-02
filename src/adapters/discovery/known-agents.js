/**
 * A small, deliberately incomplete registry of recognizable local AI/agent
 * software. Adding support for a new one is a data-table edit here, not
 * new detection code — see agent-detection.js for how it's used.
 *
 * This is NOT an exhaustive or authoritative list; it only covers the
 * runtimes named in the project brief. Absence from this list means "not
 * checked for", never "confirmed absent".
 */
export const KNOWN_AGENTS = [
  {
    id: 'ollama',
    label: 'Ollama',
    processNamePatterns: [/ollama/i],
    binaryNames: ['ollama'],
    defaultPorts: [11434],
  },
  {
    id: 'claude-code',
    label: 'Claude Code',
    processNamePatterns: [/claude/i],
    binaryNames: ['claude'],
    defaultPorts: [],
  },
  {
    id: 'openclaw',
    label: 'OpenClaw',
    processNamePatterns: [/openclaw/i],
    binaryNames: ['openclaw'],
    defaultPorts: [],
  },
  {
    id: 'hermes',
    label: 'Hermes',
    processNamePatterns: [/hermes/i],
    binaryNames: ['hermes'],
    defaultPorts: [],
  },
];
