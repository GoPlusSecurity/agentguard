import type { ScanRule } from '../../types/scanner.js';

/**
 * Data exfiltration detection rules
 */
export const EXFILTRATION_RULES: ScanRule[] = [
  {
    id: 'NET_EXFIL_UNRESTRICTED',
    description: 'Detects unrestricted network data exfiltration',
    severity: 'high',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.py', '*.md'],
    patterns: [
      // Generic POST requests (may need context analysis)
      /fetch\s*\([^)]+,\s*\{[^}]*method\s*:\s*['"`]POST['"`]/,
      /axios\.post\s*\(/,
      /requests\.post\s*\(/,
      /http\.request\s*\([^)]*method\s*:\s*['"`]POST['"`]/,
      // FormData upload
      /new\s+FormData\s*\(/,
      // File upload patterns
      /enctype\s*[:=]\s*['"`]multipart\/form-data['"`]/,
    ],
  },
  {
    id: 'WEBHOOK_EXFIL',
    description: 'Detects webhook-based data exfiltration',
    severity: 'critical',
    file_patterns: ['*'],
    patterns: [
      // Discord webhooks
      /discord(?:app)?\.com\/api\/webhooks/i,
      /discordapp\.com\/api\/webhooks/i,
      // Telegram bot API
      /api\.telegram\.org\/bot/i,
      /telegram-bot-api/i,
      // Slack webhooks
      /hooks\.slack\.com/i,
      // Generic webhook patterns
      /webhook\s*[:=]\s*['"`]https?:/i,
      /ngrok\.io/i,
      /requestbin/i,
      /pipedream/i,
      /webhook\.site/i,
    ],
  },
];

