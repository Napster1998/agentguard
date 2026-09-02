import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const CANDIDATES = [
  { relTo: 'home', segment: '.ssh', severity: 'HIGH', label: 'SSH directory' },
  { relTo: 'home', segment: path.join('.aws', 'credentials'), severity: 'CRITICAL', label: 'AWS credentials file' },
  { relTo: 'home', segment: '.aws', severity: 'HIGH', label: 'AWS config directory' },
  { relTo: 'home', segment: path.join('.config', 'gcloud'), severity: 'HIGH', label: 'gcloud config directory' },
  { relTo: 'home', segment: '.kube', severity: 'HIGH', label: 'kube config directory' },
  { relTo: 'cwd', segment: '.env', severity: 'HIGH', label: 'Environment file' },
  { relTo: 'cwd', segment: 'credentials.json', severity: 'HIGH', label: 'Credentials file' },
  { relTo: 'cwd', segment: 'secrets.yaml', severity: 'HIGH', label: 'Secrets file' },
];

/**
 * Checks EXISTENCE and PERMISSIONS ONLY — never opens or reads a
 * candidate's contents. Callers must keep it that way: only path/severity/
 * mode/isDirectory may ever end up in a finding's evidence.
 *
 * @returns {Array<{label,path,severity,isDirectory,mode}>}
 */
export function scanSensitiveResources({ homedir = os.homedir(), cwd = process.cwd(), statSync = fs.statSync } = {}) {
  const found = [];

  for (const candidate of CANDIDATES) {
    const base = candidate.relTo === 'home' ? homedir : cwd;
    const fullPath = path.join(base, candidate.segment);
    let stat;
    try {
      stat = statSync(fullPath);
    } catch {
      continue; // doesn't exist - nothing to report
    }
    found.push({
      label: candidate.label,
      path: fullPath,
      severity: candidate.severity,
      isDirectory: stat.isDirectory(),
      mode: (stat.mode & 0o777).toString(8),
    });
  }

  return found;
}
