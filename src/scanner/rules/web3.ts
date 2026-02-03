import type { ScanRule } from '../../types/scanner.js';

/**
 * Web3/Blockchain specific detection rules
 */
export const WEB3_RULES: ScanRule[] = [
  {
    id: 'PRIVATE_KEY_PATTERN',
    description: 'Detects hardcoded private keys',
    severity: 'critical',
    file_patterns: ['*'],
    patterns: [
      // Ethereum private key (64 hex chars)
      /['"`]0x[a-fA-F0-9]{64}['"`]/,
      /private[_\s]?key\s*[:=]\s*['"`]0x[a-fA-F0-9]{64}/i,
      // Generic hex key patterns
      /PRIVATE_KEY\s*[:=]\s*['"`][a-fA-F0-9]{64}/i,
    ],
  },
  {
    id: 'MNEMONIC_PATTERN',
    description: 'Detects hardcoded mnemonic phrases',
    severity: 'critical',
    file_patterns: ['*'],
    patterns: [
      // 12-word mnemonic pattern (simplified)
      /['"`]\s*\b(abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse)\b(\s+\w+){11,23}\s*['"`]/i,
      // Seed phrase keywords
      /seed[_\s]?phrase\s*[:=]\s*['"`]/i,
      /mnemonic\s*[:=]\s*['"`]/i,
      /recovery[_\s]?phrase\s*[:=]\s*['"`]/i,
    ],
  },
  {
    id: 'WALLET_DRAINING',
    description: 'Detects wallet draining patterns (approve + transferFrom)',
    severity: 'critical',
    file_patterns: ['*.js', '*.ts', '*.sol'],
    patterns: [
      // Approve max uint
      /approve\s*\([^,]+,\s*(type\s*\(\s*uint256\s*\)\s*\.max|0xffffffff|MaxUint256|MAX_UINT)/i,
      // transferFrom with approval
      /transferFrom.*approve|approve.*transferFrom/is,
      // Permit + transfer
      /permit\s*\(.*deadline/is,
    ],
  },
  {
    id: 'UNLIMITED_APPROVAL',
    description: 'Detects unlimited token approvals',
    severity: 'high',
    file_patterns: ['*.js', '*.ts', '*.sol'],
    patterns: [
      /\.approve\s*\([^,]+,\s*ethers\.constants\.MaxUint256/,
      /\.approve\s*\([^,]+,\s*2\s*\*\*\s*256\s*-\s*1/,
      /\.approve\s*\([^,]+,\s*type\(uint256\)\.max/,
      /setApprovalForAll\s*\([^,]+,\s*true\)/,
    ],
  },
  {
    id: 'DANGEROUS_SELFDESTRUCT',
    description: 'Detects selfdestruct in contracts',
    severity: 'high',
    file_patterns: ['*.sol'],
    patterns: [
      /selfdestruct\s*\(/,
      /suicide\s*\(/,
    ],
  },
  {
    id: 'HIDDEN_TRANSFER',
    description: 'Detects non-standard transfer implementations',
    severity: 'medium',
    file_patterns: ['*.sol'],
    patterns: [
      // Transfer in non-standard functions
      /function\s+(?!transfer|_transfer)\w+[^{]*\{[^}]*\.transfer\s*\(/,
      // Low-level call with value
      /\.call\{value:\s*[^}]+\}\s*\(['"`]['"`]\)/,
    ],
  },
  {
    id: 'PROXY_UPGRADE',
    description: 'Detects proxy upgrade patterns',
    severity: 'medium',
    file_patterns: ['*.sol', '*.js', '*.ts'],
    patterns: [
      /upgradeTo\s*\(/,
      /upgradeToAndCall\s*\(/,
      /\_setImplementation\s*\(/,
      /IMPLEMENTATION_SLOT/,
    ],
  },
  {
    id: 'FLASH_LOAN_RISK',
    description: 'Detects flash loan usage',
    severity: 'medium',
    file_patterns: ['*.sol', '*.js', '*.ts'],
    patterns: [
      /flashLoan\s*\(/i,
      /flash\s*Loan/i,
      /IFlashLoan/,
      /executeOperation\s*\(/,
      /AAVE.*flash/i,
    ],
  },
  {
    id: 'REENTRANCY_PATTERN',
    description: 'Detects potential reentrancy vulnerabilities',
    severity: 'high',
    file_patterns: ['*.sol'],
    patterns: [
      // External call before state change
      /\.call\{[^}]*\}\s*\([^)]*\)[^;]*;[^}]*\w+\s*[+\-*/]?=/,
      /\.transfer\s*\([^)]*\)[^;]*;[^}]*\w+\s*[+\-*/]?=/,
    ],
  },
  {
    id: 'SIGNATURE_REPLAY',
    description: 'Detects missing replay protection in signatures',
    severity: 'high',
    file_patterns: ['*.sol'],
    patterns: [
      // ecrecover without nonce check
      /ecrecover\s*\([^)]+\)/,
    ],
    validator: (content, match) => {
      // Check if nonce is used in the same function
      const fnMatch = content.match(/function\s+\w+[^{]*\{([^}]+ecrecover[^}]+)\}/s);
      if (fnMatch) {
        const fnBody = fnMatch[1];
        return !fnBody.includes('nonce');
      }
      return true;
    },
  },
];
