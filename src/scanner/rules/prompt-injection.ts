import type { ScanRule } from '../../types/scanner.js';

/**
 * Prompt injection detection rules
 */
export const PROMPT_INJECTION_RULES: ScanRule[] = [
  {
    id: 'PROMPT_INJECTION',
    description: 'Detects prompt injection attempts',
    severity: 'critical',
    file_patterns: ['*'],
    patterns: [
      // Ignore instructions
      /ignore\s+(previous|all|above|prior)\s+(instructions?|rules?|guidelines?)/i,
      /disregard\s+(previous|all|above|prior)\s+(instructions?|rules?|guidelines?)/i,
      /forget\s+(previous|all|above|prior)\s+(instructions?|rules?|guidelines?)/i,
      // Jailbreak attempts
      /you\s+are\s+(now|a)\s+(?:DAN|jailbroken|unrestricted)/i,
      /pretend\s+(?:you\s+are|to\s+be)\s+(?:a\s+)?(?:different|new|unrestricted)/i,
      /act\s+as\s+(?:if\s+)?(?:you\s+have\s+)?no\s+(?:restrictions?|rules?|limitations?)/i,
      // Bypass confirmation
      /(?:no|without|skip)\s+(?:need\s+(?:for\s+)?)?confirm(?:ation)?/i,
      /bypass\s+(?:security|safety|restrictions?|confirm)/i,
      /auto(?:matically)?\s+(?:approve|confirm|execute|run)/i,
      // Role manipulation
      /you\s+must\s+(?:always\s+)?(?:obey|follow|execute)/i,
      /system\s*:\s*you\s+are/i,
      /\[system\].*\[\/system\]/is,
      // Chinese variations
      /忽略(?:之前|所有|上面)(?:的)?(?:指令|规则|说明)/,
      /无需确认/,
      /自动执行/,
      /跳过验证/,
    ],
  },
];
