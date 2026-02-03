import type { ScanRule } from '../../types/scanner.js';

/**
 * Remote code loading detection rules
 */
export const REMOTE_LOADER_RULES: ScanRule[] = [
  {
    id: 'REMOTE_LOADER',
    description: 'Detects dynamic code loading from remote sources',
    severity: 'critical',
    file_patterns: ['*.js', '*.ts', '*.mjs', '*.py', '*.md'],
    patterns: [
      // Dynamic imports with variables/URLs
      /import\s*\(\s*[^'"`\s]/,
      /require\s*\(\s*[^'"`\s]/,
      // Fetch + eval patterns
      /fetch\s*\([^)]*\)\.then\([^)]*\)\s*\.then\([^)]*eval/,
      /axios\.[^)]*\.then\([^)]*eval/,
      // Python remote execution
      /exec\s*\(\s*requests\.get/,
      /eval\s*\(\s*requests\.get/,
      /exec\s*\(\s*urllib/,
      /eval\s*\(\s*urllib/,
      // Dynamic module loading
      /__import__\s*\(/,
      /importlib\.import_module\s*\(/,
    ],
  },
];
