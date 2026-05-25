/**
 * @file cleanup_chars.js
 * @description Maintenance script to remove non-ASCII characters for repository compliance.
 */
const fs = require('fs');
const files = [
  'src/core/ActionNormalizer.ts',
  'src/core/SecurityEngine.ts',
  'src/adapters/HookAdapter.ts',
  'src/adapters/LegacyAdapter.ts'
];

files.forEach(file => {
  if (fs.existsSync(file)) {
    const content = fs.readFileSync(file, 'utf8');
    const cleaned = content.replace(/[^\x00-\x7F]/g, '');
    fs.writeFileSync(file, cleaned, 'utf8');
    process.stdout.write('Cleaned: ' + file + '\n');
  }
});
