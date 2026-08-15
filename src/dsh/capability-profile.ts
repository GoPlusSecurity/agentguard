import { walkDirectory } from '../scanner/file-walker.js';
import type { DshCapabilityProfile, DshDetection } from './types.js';

const PATTERNS = {
  fileRead: /(?:\breadFile(?:Sync)?\s*\(|\breaddir(?:Sync)?\s*\(|\bcreateReadStream\s*\(|\bfs\.promises\.(?:readFile|readdir)|from\s+['"]node:fs['"])/,
  fileWrite: /(?:\bwriteFile(?:Sync)?\s*\(|\bappendFile(?:Sync)?\s*\(|\bcreateWriteStream\s*\(|\bmkdir(?:Sync)?\s*\(|\brm(?:Sync)?\s*\(|\bunlink(?:Sync)?\s*\(|\brename(?:Sync)?\s*\()/,
  networkAccess: /(?:\bfetch\s*\(|\baxios(?:\.|\s*\()|from\s+['"](?:node:)?https?['"]|require\s*\(\s*['"](?:node:)?https?['"]|\bWebSocket\s*\(|\bEventSource\s*\()/,
  shellExec: /(?:from\s+['"](?:node:)?child_process['"]|require\s*\(\s*['"](?:node:)?child_process['"]|(?<!\.)\b(?:exec|execSync|spawn|spawnSync|execFile|fork)\s*\()/,
  envAccess: /(?:process\.env(?:\.|\[)|\bdotenv\b|\.env\b)/,
  providerAccess: /(?:ctx\.llm|dsh-llm|provider(?:Name)?\s*:|model\s*:|credentials?)/i,
  uiInjection: /(?:dsh\.client|ConversationNodeDefinition|session\/event|assistant\/chunk|ctx\.agents|createRoot\s*\(|ReactDOM|@deepseek-ai\/dsh-client)/,
  sessionAccess: /(?:ctx\.sessions|session\/event|tool\/result|assistant\/message|dsh-session)/,
  storageAccess: /(?:session-persistence|ctx\.storage|dsh-settings|sqlite|\.sessions|persistence)/i,
  toolRegistryMutation: /(?:ctx\.tools\.(?:register|restrict|guard)|tools\/(?:pre-execute|execute|post-execute|result)|dsh-tool-)/,
  runtimeMutation: /(?:agent\/(?:pre-step|request|turn-stopping)|dsh-agent-loop|system-prompt\/assemble|cordis-plugin-(?:loader|hmr))/,
} as const;

/** Infer the plugin's effective capabilities from source, metadata, and Cordis rows. */
export async function buildCapabilityProfile(rootDir: string, detection: DshDetection): Promise<DshCapabilityProfile> {
  const files = await walkDirectory(rootDir);
  const combined = files
    .filter(file => file.extension !== '.md')
    .map(file => file.content)
    .join('\n');
  const rowNames = detection.cordis.rows.map(row => `${row.id ?? ''} ${row.name ?? ''}`).join('\n');
  const metadata = `${detection.package.description ?? ''}\n${detection.package.dependencies.join('\n')}\n${rowNames}`;
  const corpus = `${combined}\n${metadata}`;

  return {
    fileRead: PATTERNS.fileRead.test(corpus),
    fileWrite: PATTERNS.fileWrite.test(corpus),
    networkAccess: PATTERNS.networkAccess.test(corpus),
    shellExec: PATTERNS.shellExec.test(corpus),
    envAccess: PATTERNS.envAccess.test(corpus),
    providerAccess: PATTERNS.providerAccess.test(corpus),
    uiInjection: detection.package.hasClientExtension || PATTERNS.uiInjection.test(corpus),
    sessionAccess: PATTERNS.sessionAccess.test(corpus),
    storageAccess: PATTERNS.storageAccess.test(corpus),
    toolRegistryMutation: PATTERNS.toolRegistryMutation.test(corpus),
    runtimeMutation: detection.cordis.rows.some(row => row.operation === 'replace') || PATTERNS.runtimeMutation.test(corpus),
  };
}
