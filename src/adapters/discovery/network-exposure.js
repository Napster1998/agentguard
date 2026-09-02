import { listListeningPorts as defaultListListeningPorts } from '../host/listening-ports.js';

const LOCAL_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

function isExternallyBound(host) {
  return !LOCAL_HOSTS.has(host);
}

/**
 * Cross-references the machine's own listening-port table against detected
 * agents' known default ports (e.g. Ollama on 11434), flagging any that are
 * bound beyond localhost. This is local self-inspection only — it never
 * connects out to anything, and it is not a general port scanner: only
 * ports belonging to a *detected* agent are considered.
 *
 * @returns {Promise<Array<{agentId,label,host,port,externallyBound}>>}
 */
export async function assessNetworkExposure({ detectedAgents, listListeningPorts = defaultListListeningPorts } = {}) {
  const ports = await listListeningPorts();
  const results = [];

  for (const agent of detectedAgents) {
    for (const defaultPort of agent.defaultPorts || []) {
      const match = ports.find((p) => p.port === defaultPort);
      if (!match) continue;
      results.push({
        agentId: agent.id,
        label: agent.label,
        host: match.host,
        port: match.port,
        externallyBound: isExternallyBound(match.host),
      });
    }
  }

  return results;
}
