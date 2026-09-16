import type { ScanRule } from '../../types/scanner.js';
import { classifyLlmEndpoint } from '../../runtime/llm-endpoints.js';

const ENDPOINT_ASSIGNMENT = /["']?(?:OPENAI_BASE_URL|OPENAI_API_BASE|ANTHROPIC_BASE_URL|ANTHROPIC_API_URL|GEMINI_BASE_URL|GOOGLE_GEMINI_BASE_URL|GOOGLE_API_BASE|AZURE_OPENAI_ENDPOINT|LLM_BASE_URL|MODEL_BASE_URL|(?:openai|anthropic|gemini)[_-]?(?:baseURL|base_url|api_base|endpoint))["']?\s*[:=]\s*["']?(https?:\/\/[^\s"'`,}]+)/i;
const CREDENTIAL_READ = /(?:process\.env(?:\.|\[['"])(?:OPENAI|ANTHROPIC|GEMINI|GOOGLE|AZURE_OPENAI|MISTRAL|COHERE|GROQ|XAI)[A-Z0-9_]*(?:API_KEY|TOKEN)|os\.(?:getenv|environ)(?:\(|\[)\s*["'](?:OPENAI|ANTHROPIC|GEMINI|GOOGLE|AZURE_OPENAI|MISTRAL|COHERE|GROQ|XAI)[A-Z0-9_]*(?:API_KEY|TOKEN)|\$\{?(?:OPENAI|ANTHROPIC|GEMINI|GOOGLE|AZURE_OPENAI|MISTRAL|COHERE|GROQ|XAI)[A-Z0-9_]*(?:API_KEY|TOKEN)\}?)/i;
const AGENT_CONFIG_TARGET = /(?:\.(?:zshrc|bashrc|bash_profile|profile)|powershell[^\n]*(?:profile|\.ps1)|\.codex[\\/]config\.toml|\.claude[\\/]settings(?:\.local)?\.json|\.hermes[\\/]config\.ya?ml|openclaw(?:\.config)?\.json|dsh[^\s"']*(?:config|profile)[^\s"']*)/i;
const URL_PATTERN = /https?:\/\/[^\s"'`),;}]+/gi;

export const LLM_RELAY_RULES: ScanRule[] = [
  {
    id: 'LLM_ENDPOINT_OVERRIDE',
    description: 'Detects LLM base URL overrides that target unknown or high-risk endpoints',
    severity: 'high',
    file_patterns: ['*'],
    patterns: [ENDPOINT_ASSIGNMENT],
    validator: (_content, match) => isUntrustedEndpoint(match[1] ?? ''),
  },
  {
    id: 'RELAY_KEY_FORWARDING',
    description: 'Detects model credential reads forwarded to an unknown or high-risk endpoint in the same local code window',
    severity: 'critical',
    file_patterns: ['*.js', '*.ts', '*.jsx', '*.tsx', '*.mjs', '*.cjs', '*.py', '*.sh', '*.bash'],
    patterns: [CREDENTIAL_READ],
    validator: (content, match, _filePath, matchOffset = 0) => {
      const region = localWindow(content, matchOffset, match[0].length);
      if (!/(?:authorization|bearer|x-api-key|api[_-]?key|headers?)/i.test(region)) return false;
      if (!/(?:fetch|axios|requests?\.|urllib|http\.request|curl|wget)/i.test(region)) return false;
      return extractUrls(region).some(isUntrustedEndpoint);
    },
  },
  {
    id: 'RELAY_INSTALL_SCRIPT',
    description: 'Detects install scripts that persist an untrusted LLM endpoint into shell or agent configuration',
    severity: 'critical',
    file_patterns: ['*.sh', '*.bash', '*.js', '*.ts', '*.py', '*.md'],
    patterns: [AGENT_CONFIG_TARGET],
    validator: (content, match, _filePath, matchOffset = 0) => {
      const region = localWindow(content, matchOffset, match[0].length, 2_000);
      if (!/(?:>>?|\btee\b|sed\s+-i|writeFile|write_text|set-content|add-content|out-file)/i.test(region)) return false;
      const endpoint = region.match(ENDPOINT_ASSIGNMENT)?.[1];
      return Boolean(endpoint && isUntrustedEndpoint(endpoint));
    },
  },
];

function isUntrustedEndpoint(value: string): boolean {
  const tier = classifyLlmEndpoint(value).tier;
  return tier === 'T3' || tier === 'T4';
}

function extractUrls(value: string): string[] {
  return [...value.matchAll(URL_PATTERN)].map((match) => match[0]);
}

function localWindow(content: string, matchOffset: number, matchLength: number, radius = 1_500): string {
  return content.slice(Math.max(0, matchOffset - radius), matchOffset + matchLength + radius);
}
