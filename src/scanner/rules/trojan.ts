import type { ScanRule } from '../../types/scanner.js';

/**
 * Trojanized distribution and social engineering detection rules
 */
export const TROJAN_RULES: ScanRule[] = [
  {
    id: 'TROJAN_DISTRIBUTION',
    description: 'Detects trojanized binary distribution patterns (download + password + execute)',
    severity: 'critical',
    file_patterns: ['*.md'],
    patterns: [
      // GitHub release binary downloads with password
      /releases\/download\/.*\.(zip|tar|exe|dmg|appimage)/i,
      // Direct binary download + password combination
      /password\s*[:=]\s*['"`]?\w+['"`]?/i,
      // Run executable instructions
      /\.\/\w+.*(?:run|execute|start|launch)/i,
      // chmod +x pattern (make executable)
      /chmod\s+\+x\s/,
    ],
    validator: (content: string) => {
      // Must have at least 2 of: download URL, password, execute instruction
      const hasDownload = /https?:\/\/.*(?:releases\/download|\.zip|\.tar|\.exe|\.dmg)/i.test(content);
      const hasPassword = /password\s*[:=]/i.test(content);
      const hasExecute = /(?:chmod\s+\+x|\.\/\w+|run\s+the|execute)/i.test(content);
      const signals = [hasDownload, hasPassword, hasExecute].filter(Boolean).length;
      return signals >= 2;
    },
  },
  {
    id: 'SUSPICIOUS_PASTE_URL',
    description: 'Detects URLs to paste sites and code-sharing platforms',
    severity: 'high',
    file_patterns: ['*'],
    patterns: [
      /glot\.io\/snippets\//i,
      /pastebin\.com\//i,
      /hastebin\.com\//i,
      /paste\.ee\//i,
      /dpaste\.org\//i,
      /rentry\.co\//i,
      /ghostbin\.com\//i,
      /pastie\.io\//i,
    ],
  },
  {
    id: 'SUSPICIOUS_IP',
    description: 'Detects hardcoded public IP addresses',
    severity: 'medium',
    file_patterns: ['*'],
    patterns: [
      // IPv4 addresses (will use validator to exclude private ranges)
      /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/,
    ],
    validator: (content: string, match: RegExpMatchArray) => {
      const ip = match[1] || match[0];
      const parts = ip.split('.').map(Number);
      if (parts.some(p => p > 255)) return false;
      // Exclude private/local ranges
      if (parts[0] === 127) return false;  // loopback
      if (parts[0] === 0) return false;    // 0.x.x.x
      if (parts[0] === 10) return false;   // 10.x.x.x
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false; // 172.16-31.x.x
      if (parts[0] === 192 && parts[1] === 168) return false; // 192.168.x.x
      if (parts[0] === 169 && parts[1] === 254) return false; // link-local
      // Exclude common version-like patterns (e.g. 1.0.0.0, 2.0.0.0)
      if (parts[1] === 0 && parts[2] === 0 && parts[3] === 0) return false;
      return true;
    },
  },
  {
    id: 'SOCIAL_ENGINEERING',
    description: 'Detects social engineering pressure language in skill instructions',
    severity: 'medium',
    file_patterns: ['*.md'],
    patterns: [
      /CRITICAL\s+REQUIREMENT/i,
      /WILL\s+NOT\s+WORK\s+WITHOUT/i,
      /MANDATORY.*(?:install|download|run|execute)/i,
      /you\s+MUST\s+(?:install|download|run|execute|paste)/i,
      /paste\s+(?:this\s+)?into\s+(?:your\s+)?[Tt]erminal/i,
      /IMPORTANT:\s*(?:you\s+)?must/i,
    ],
    validator: (content: string) => {
      // Only flag if there's also a command execution instruction nearby
      return /(?:curl|wget|bash|sh|\.\/|chmod|npm\s+run|node\s+)/i.test(content);
    },
  },
];
