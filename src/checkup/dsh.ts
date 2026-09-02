import { basename } from 'node:path';
import { scanDshPlugin } from '../dsh/scan.js';

export interface DshCheckupFinding {
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  text: string;
}

export interface DshCheckupScanResult {
  pluginsScanned: number;
  scoreDeduction: number;
  findings: DshCheckupFinding[];
}

/** Scan a bounded list of installed DSH plugins without aborting on one operational failure. */
export async function scanDshPluginsForCheckup(pluginDirs: string[]): Promise<DshCheckupScanResult> {
  const findings: DshCheckupFinding[] = [];
  let pluginsScanned = 0;
  let scoreDeduction = 0;

  for (const dir of pluginDirs) {
    try {
      const report = await scanDshPlugin(dir);
      pluginsScanned += 1;
      if (report.riskLevel === 'critical') scoreDeduction += 15;
      if (report.riskLevel === 'high') scoreDeduction += 8;
      if (report.riskLevel === 'medium') scoreDeduction += 3;
      if (report.riskLevel !== 'low') {
        findings.push({
          severity: riskLevelToSeverity(report.riskLevel),
          text: `${report.identity.name}: ${report.summary}${report.riskTags.length ? ` (${report.riskTags.join(', ')})` : ''}`,
        });
      }
    } catch (err) {
      scoreDeduction += 8;
      findings.push({
        severity: 'HIGH',
        text: `${basename(dir)}: DSH plugin scan failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  return { pluginsScanned, scoreDeduction, findings };
}

function riskLevelToSeverity(risk: string): DshCheckupFinding['severity'] {
  if (risk === 'critical') return 'CRITICAL';
  if (risk === 'high') return 'HIGH';
  if (risk === 'medium') return 'MEDIUM';
  return 'LOW';
}
