import { walkDirectory } from '../scanner/file-walker.js';
import type { DshCapabilityProfile, DshDetection, DshPluginKind } from './types.js';

const HARMLESS_LABEL = /(?:\btheme\b|\bskin\b|\bwallpaper\b|desktop[ -]?companion|\bmascot\b|\bkawaii\b|\bmaid\b|\bwhale\b|\bpet\b)/i;

/** Classify the primary DSH plugin role using explicit metadata before heuristics. */
export async function classifyDshPlugin(
  rootDir: string,
  detection: DshDetection,
  capabilities: DshCapabilityProfile,
): Promise<DshPluginKind> {
  if (!detection.isDshPlugin) return 'unknown';
  if (detection.package.profileBundles.length > 0) return 'profile';
  if (detection.package.bundlePatch) return 'bundle';

  const files = await walkDirectory(rootDir);
  const identityText = `${detection.package.name ?? ''}\n${detection.package.description ?? ''}`;
  const text = `${identityText}\n${files.map(file => file.content).join('\n')}`;
  if (HARMLESS_LABEL.test(identityText)) return capabilities.uiInjection ? 'theme' : 'ui';
  if (detection.package.hasClientExtension) return 'ui';
  if (capabilities.toolRegistryMutation && /ctx\.tools\.register|dsh-tool-/.test(text)) return 'tool';
  if (/workflow|automation|ctx\.workflow/i.test(text)) return 'workflow';
  if (capabilities.providerAccess && /provider|adapter|ctx\.llm/i.test(text)) return 'provider';
  if (capabilities.uiInjection) return 'ui';
  if (capabilities.runtimeMutation) return 'runtime';
  return 'unknown';
}

/** Detect a benign-looking product label paired with elevated capabilities. */
export function hasHarmlessCapabilityMismatch(
  detection: DshDetection,
  kind: DshPluginKind,
  capabilities: DshCapabilityProfile,
): boolean {
  const label = `${detection.package.name ?? ''} ${detection.package.description ?? ''}`;
  const looksHarmless = kind === 'theme' || kind === 'ui' || HARMLESS_LABEL.test(label);
  return looksHarmless && unexpectedHarmlessCapabilities(capabilities).length > 0;
}

/** High-risk capabilities that are unexpected for a benign-looking UI extension. */
export function unexpectedHarmlessCapabilities(capabilities: DshCapabilityProfile): Array<keyof DshCapabilityProfile> {
  const unexpected: Array<keyof DshCapabilityProfile> = [];
  if (capabilities.shellExec) unexpected.push('shellExec');
  if (capabilities.fileWrite) unexpected.push('fileWrite');
  if (capabilities.runtimeMutation) unexpected.push('runtimeMutation');
  // Network-only UI behavior can be legitimate; environment access plus network can exfiltrate secrets.
  if (capabilities.envAccess && capabilities.networkAccess) unexpected.push('envAccess', 'networkAccess');
  return unexpected;
}
