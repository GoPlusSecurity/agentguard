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
      for (const finding of report.findings) {
        const severity = riskLevelToSeverity(finding.severity);
        if (severity === 'CRITICAL') scoreDeduction += 15;
        else if (severity === 'HIGH') scoreDeduction += 8;
        else if (severity === 'MEDIUM') scoreDeduction += 3;
        else continue;
        findings.push({
          severity,
          text: `${finding.ruleId} in ${report.identity.name}:${finding.file || '?'}:${finding.line || '?'}`,
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

  return { pluginsScanned, scoreDeduction: Math.min(100, scoreDeduction), findings };
}

function riskLevelToSeverity(risk: string): DshCheckupFinding['severity'] {
  if (risk === 'critical') return 'CRITICAL';
  if (risk === 'high') return 'HIGH';
  if (risk === 'medium') return 'MEDIUM';
  return 'LOW';
}
