import { walkDirectory } from '../scanner/file-walker.js';
import { parseCordisConfigs } from './parse-cordis-patch.js';
import { parseDshPackage } from './parse-package.js';
import type { DshDetection } from './types.js';

const SOURCE_SIGNAL = /ctx\.tools\.(?:register|guard)|tools\/(?:pre-execute|execute|post-execute|result)|@deepseek-ai\/dsh-|@deepseek-ai\/cordis/;
const README_SIGNAL = /DeepSeek Harness|\bDSH\b|dsh-plugin|Everything is a Plugin/i;

/** Detect whether a directory is a DSH plugin, profile, bundle, or related extension. */
export async function detectDshPlugin(rootDir: string): Promise<DshDetection> {
  const [pkg, cordis, files] = await Promise.all([
    parseDshPackage(rootDir),
    parseCordisConfigs(rootDir),
    walkDirectory(rootDir),
  ]);
  const signals: string[] = [];
  let score = 0;

  if (pkg.bundlePatch) {
    signals.push(`package.json declares dsh.bundle.patch (${pkg.bundlePatch})`);
    score += 4;
  }
  if (pkg.profileBundles.length > 0) {
    signals.push(`package.json declares dsh.profile.bundles (${pkg.profileBundles.length})`);
    score += 4;
  }
  if (pkg.hasClientExtension) {
    signals.push(`package.json declares dsh.client${pkg.clientPlatform ? ` for ${pkg.clientPlatform}` : ''}`);
    score += 3;
  }
  if (cordis.files.length > 0) {
    signals.push(`found ${cordis.files.length} Cordis configuration file${cordis.files.length === 1 ? '' : 's'}`);
    score += 2;
  }
  if (pkg.dependencies.some(name => name.startsWith('@deepseek-ai/dsh-') || name === '@deepseek-ai/cordis')) {
    signals.push('package depends on DSH or Cordis runtime packages');
    score += 2;
  }
  if (files.some(file => SOURCE_SIGNAL.test(file.content))) {
    signals.push('source uses DSH/Cordis plugin APIs');
    score += 2;
  }
  if (files.some(file => file.extension === '.md' && README_SIGNAL.test(file.content))) {
    signals.push('documentation identifies the project as DSH-related');
    score += 1;
  }

  return {
    isDshPlugin: score >= 2,
    confidence: score >= 4 ? 'high' : score >= 2 ? 'medium' : score === 1 ? 'low' : 'none',
    signals,
    package: pkg,
    cordis,
  };
}
