import { KNOWN_AGENTS } from './known-agents.js';
import { listProcesses as defaultListProcesses } from '../host/process-list.js';
import { findOnPath as defaultFindOnPath } from '../host/path-lookup.js';

/**
 * Cross-references live processes and PATH lookups against KNOWN_AGENTS.
 * Both data sources are injectable so tests exercise the matching logic
 * without depending on what's actually installed on the machine running
 * them (this is the pattern used throughout src/adapters/discovery).
 *
 * @returns {Promise<Array<{id:string,label:string,detectedVia:string,evidence:string,defaultPorts:number[]}>>}
 */
export async function detectAgents({
  listProcesses = defaultListProcesses,
  findOnPath = defaultFindOnPath,
  registry = KNOWN_AGENTS,
} = {}) {
  const processes = await listProcesses();
  const detections = [];

  for (const agent of registry) {
    const matchedProcess = processes.find((p) => agent.processNamePatterns.some((re) => re.test(p.name)));
    if (matchedProcess) {
      detections.push({
        id: agent.id,
        label: agent.label,
        detectedVia: 'process',
        evidence: `Process "${matchedProcess.name}" (pid ${matchedProcess.pid})`,
        defaultPorts: agent.defaultPorts,
      });
      continue;
    }

    for (const binary of agent.binaryNames) {
      // eslint-disable-next-line no-await-in-loop
      const foundPath = await findOnPath(binary);
      if (foundPath) {
        detections.push({
          id: agent.id,
          label: agent.label,
          detectedVia: 'path',
          evidence: `"${binary}" found on PATH (${foundPath})`,
          defaultPorts: agent.defaultPorts,
        });
        break;
      }
    }
  }

  return detections;
}
