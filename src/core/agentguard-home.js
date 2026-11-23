import os from 'node:os';
import path from 'node:path';

/**
 * Where AgentGuard keeps its own state: the generated policy, the shared
 * audit log, and config backups. Defaults to ~/.agentguard; the
 * AGENTGUARD_HOME environment variable overrides it (used by tests and by
 * the demo so neither ever reads or writes a real user's state).
 */
export function homePaths({ env = process.env, homedir = os.homedir() } = {}) {
  const home = env.AGENTGUARD_HOME ? path.resolve(env.AGENTGUARD_HOME) : path.join(homedir, '.agentguard');
  return {
    home,
    policy: path.join(home, 'policy.yaml'),
    // The Antigravity hook's own policy (a coding-agent profile, see
    // policy/antigravity-policy.yaml), kept separate so installing the hook
    // never changes what the MCP gateway enforces.
    antigravityPolicy: path.join(home, 'antigravity-policy.yaml'),
    audit: path.join(home, 'audit.jsonl'),
    backups: path.join(home, 'backups'),
  };
}
