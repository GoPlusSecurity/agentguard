import type { ScanRule } from '../../../types/scanner.js';

/** DSH-specific composition and capability rules used by the DSH scanner. */
export const DSH_RULES: ScanRule[] = [
  {
    id: 'INSTALL_SCRIPT',
    description: 'Package installation lifecycle script can execute code during installation',
    severity: 'high',
    file_patterns: ['*.json'],
    patterns: [/['"](?:preinstall|postinstall|prepare)['"]\s*:/],
  },
  {
    id: 'NETWORK_ACCESS',
    description: 'Plugin can make outbound network requests',
    severity: 'medium',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.jsx', '*.tsx'],
    patterns: [
      /\bfetch\s*\(/,
      /\baxios(?:\.|\s*\()/,
      /from\s+['"](?:node:)?https?['"]/,
      /require\s*\(\s*['"](?:node:)?https?['"]\s*\)/,
      /\bWebSocket\s*\(/,
    ],
  },
  {
    id: 'FILE_READ_ACCESS',
    description: 'Plugin can read files or enumerate local directories',
    severity: 'medium',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.jsx', '*.tsx'],
    patterns: [/\breadFile(?:Sync)?\s*\(/, /\breaddir(?:Sync)?\s*\(/, /\bcreateReadStream\s*\(/],
  },
  {
    id: 'FILE_WRITE_ACCESS',
    description: 'Plugin can write, move, or remove local files',
    severity: 'high',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.jsx', '*.tsx'],
    patterns: [
      /\bwriteFile(?:Sync)?\s*\(/,
      /\bappendFile(?:Sync)?\s*\(/,
      /\bcreateWriteStream\s*\(/,
      /\b(?:rm|unlink|rename)(?:Sync)?\s*\(/,
    ],
  },
  {
    id: 'DSH_PATCH_OVERRIDE',
    description: 'Cordis patch replaces an existing DSH composition row',
    severity: 'high',
    file_patterns: ['*.yml', '*.yaml'],
    patterns: [/-\s+id:\s*(?:llm|agent|tools?|session|storage|credentials?|sandbox|approval|permission|webserver|runtime)\b/i],
  },
  {
    id: 'DSH_TOOL_REGISTRY_MUTATION',
    description: 'Plugin registers, restricts, guards, or intercepts DSH tools',
    severity: 'high',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.cjs'],
    patterns: [
      /ctx\.tools\.(?:register|restrict|guard)\s*\(/,
      /ctx\.on\s*\(\s*['"]tools\/(?:pre-execute|execute|post-execute)['"]/,
    ],
  },
  {
    id: 'DSH_PROVIDER_MUTATION',
    description: 'Plugin can change model/provider or credential routing',
    severity: 'high',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.yml', '*.yaml'],
    patterns: [
      /ctx\.llm\./,
      /@deepseek-ai\/dsh-llm-/,
      /(?:id|name):\s*(?:llm|provider|credentials?)\b/i,
    ],
  },
  {
    id: 'DSH_RUNTIME_MUTATION',
    description: 'Plugin intercepts core agent, prompt, or runtime lifecycle behavior',
    severity: 'high',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.yml', '*.yaml'],
    patterns: [
      /ctx\.on\s*\(\s*['"]agent\/(?:pre-step|request|turn-stopping)['"]/,
      /ctx\.on\s*\(\s*['"]system-prompt\/assemble['"]/,
      /@deepseek-ai\/dsh-agent-loop/,
      /(?:id|name):\s*(?:agent|runtime|hmr|loader)\b/i,
    ],
  },
  {
    id: 'DSH_SESSION_STORAGE_ACCESS',
    description: 'Plugin accesses DSH session, settings, or persistence services',
    severity: 'medium',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.cjs', '*.yml', '*.yaml'],
    patterns: [
      /ctx\.sessions\./,
      /ctx\.on\s*\(\s*['"]session\/event['"]/,
      /@deepseek-ai\/dsh-(?:session|settings|credentials)/,
      /(?:id|name):\s*(?:session|storage|persistence|settings)\b/i,
    ],
  },
  {
    id: 'DSH_THEME_ELEVATED_CAPABILITY',
    description: 'Benign-looking UI, theme, skin, or pet plugin requests elevated capabilities',
    severity: 'high',
    file_patterns: ['*'],
    patterns: [/(?!)/],
  },
];
