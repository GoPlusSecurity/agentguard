import { access } from 'node:fs/promises';
import { join } from 'node:path';
import type { RiskLevel, RiskTag } from '../types/scanner.js';
import type {
  DshFinding,
  DshFindingSource,
  DshReviewPriority,
  DshRuntimeRelevance,
} from './types.js';

const TEST_PATH = /(?:^|\/)(?:tests?|__tests__|fixtures?|evals?|specs?)(?:\/|$)|\.(?:test|spec)\.[^/]+$/i;
const EXAMPLE_PATH = /(?:^|\/)(?:examples?|demos?|samples?)(?:\/|$)/i;
const DOC_PATH = /(?:^|\/)(?:docs?|documentation)(?:\/|$)|(?:^|\/)readme(?:\.[^/]+)?\.md$|\.md$/i;
const BUILD_PATH = /(?:^|\/)(?:scripts?|tools?|tasks?)(?:\/|$)/i;
const DATA_PATH = /(?:^|\/)(?:data|assets?|resources?)(?:\/|$)/i;
const GENERATED_PATH = /(?:^|\/)(?:dist|build|lib|generated|vendor)(?:\/|$)/i;
const CORDIS_FILE = /(?:^|\/)cordis(?:\.patch)?\.ya?ml$/i;

export function classifyFindingPath(file: string, tag: RiskTag): {
  sourceCategory: DshFindingSource;
  runtimeRelevance: DshRuntimeRelevance;
} {
  const normalized = file.replace(/\\/g, '/');
  if (tag === 'DSH_THEME_ELEVATED_CAPABILITY') {
    return { sourceCategory: 'derived', runtimeRelevance: 'unknown' };
  }
  if (tag === 'INSTALL_SCRIPT' || normalized === 'package.json') {
    return { sourceCategory: 'installation', runtimeRelevance: 'direct' };
  }
  if (tag === 'DSH_PATCH_OVERRIDE' || CORDIS_FILE.test(normalized)) {
    return { sourceCategory: 'configuration', runtimeRelevance: 'direct' };
  }
  if (TEST_PATH.test(normalized)) return { sourceCategory: 'test', runtimeRelevance: 'unlikely' };
  if (EXAMPLE_PATH.test(normalized)) return { sourceCategory: 'example', runtimeRelevance: 'unlikely' };
  if (DOC_PATH.test(normalized)) return { sourceCategory: 'documentation', runtimeRelevance: 'unlikely' };
  if (BUILD_PATH.test(normalized)) return { sourceCategory: 'build', runtimeRelevance: 'indirect' };
  if (DATA_PATH.test(normalized)) return { sourceCategory: 'data', runtimeRelevance: 'unknown' };
  if (/\.(?:js|ts|jsx|tsx|mjs|cjs|py|sh|bash)$/i.test(normalized)) {
    return { sourceCategory: 'runtime', runtimeRelevance: 'direct' };
  }
  return { sourceCategory: 'unknown', runtimeRelevance: 'unknown' };
}

async function hasSourceMap(rootDir: string, file: string): Promise<boolean> {
  if (!/\.(?:js|mjs|cjs)$/i.test(file)) return false;
  try {
    await access(join(rootDir, `${file}.map`));
    return true;
  } catch {
    return false;
  }
}

export async function addFindingContext(rootDir: string, findings: DshFinding[]): Promise<void> {
  await Promise.all(findings.map(async finding => {
    const context = classifyFindingPath(finding.file, finding.ruleId);
    finding.sourceCategory = context.sourceCategory;
    finding.runtimeRelevance = context.runtimeRelevance;
    finding.likelyGenerated = GENERATED_PATH.test(finding.file.replace(/\\/g, '/'))
      && await hasSourceMap(rootDir, finding.file);
  }));

  const derivedRelevance: DshRuntimeRelevance = findings.some(finding =>
    finding.ruleId !== 'DSH_THEME_ELEVATED_CAPABILITY'
      && (finding.runtimeRelevance === 'direct' || finding.runtimeRelevance === 'indirect'))
    ? 'direct'
    : 'unlikely';
  for (const finding of findings) {
    if (finding.sourceCategory === 'derived') finding.runtimeRelevance = derivedRelevance;
  }
}

export function runtimeSurfaceTags(findings: DshFinding[]): RiskTag[] {
  return [...new Set(findings
    .filter(finding => finding.runtimeRelevance === 'direct' || finding.runtimeRelevance === 'indirect')
    .map(finding => finding.ruleId))];
}

const URGENT_RUNTIME_TAGS = new Set<RiskTag>([
  'AUTO_UPDATE',
  'REMOTE_LOADER',
  'NET_EXFIL_UNRESTRICTED',
  'WEBHOOK_EXFIL',
  'PRIVATE_KEY_PATTERN',
  'MNEMONIC_PATTERN',
]);

export function calculateReviewPriority(
  repositoryRisk: RiskLevel,
  runtimeRisk: RiskLevel,
  runtimeTags: RiskTag[],
): DshReviewPriority {
  if (runtimeRisk === 'critical' && runtimeTags.some(tag => URGENT_RUNTIME_TAGS.has(tag))) return 'urgent';
  if (runtimeRisk === 'critical'
    && runtimeTags.includes('INSTALL_SCRIPT')
    && (runtimeTags.includes('SHELL_EXEC') || runtimeTags.includes('REMOTE_LOADER'))
    && (runtimeTags.includes('NETWORK_ACCESS') || runtimeTags.includes('READ_ENV_SECRETS') || runtimeTags.includes('OBFUSCATION'))) {
    return 'urgent';
  }
  if (runtimeRisk === 'critical' || runtimeTags.includes('DSH_PATCH_OVERRIDE')) return 'high';
  if (runtimeRisk === 'high' || repositoryRisk === 'critical' || repositoryRisk === 'high') return 'elevated';
  return 'routine';
}
