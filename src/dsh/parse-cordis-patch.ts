import { readFile, stat } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { glob } from 'glob';
import { parseDocument, type ScalarTag } from 'yaml';
import type { DshCordisAnalysis, DshCordisRow } from './types.js';
import { MAX_SCANNABLE_FILE_BYTES } from '../scanner/file-walker.js';

const CORDIS_FILES = ['**/cordis.yml', '**/cordis.yaml', '**/cordis.patch.yml', '**/cordis.patch.yaml'];
const JS_EXPRESSION_TAG: ScalarTag = {
  tag: 'tag:yaml.org,2002:js',
  resolve: value => value,
};

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function addRow(rows: DshCordisRow[], value: unknown, file: string, operation: DshCordisRow['operation']): void {
  const row = asRecord(value);
  if (!row) return;
  rows.push({
    file,
    id: typeof row.id === 'string' ? row.id : undefined,
    name: typeof row.name === 'string' ? row.name : undefined,
    operation,
    hasConfig: Object.hasOwn(row, 'config'),
    disabled: row.disabled === true || typeof row.disabled === 'string',
  });
}

function collectRows(
  value: unknown,
  file: string,
  defaultOperation: 'entry' | 'replace' = basename(file).includes('.patch.') ? 'replace' : 'entry',
): DshCordisRow[] {
  const rows: DshCordisRow[] = [];
  if (!Array.isArray(value)) return rows;
  for (const item of value) {
    const record = asRecord(item);
    if (!record) continue;
    if (Array.isArray(record.insert)) {
      for (const inserted of record.insert) addRow(rows, inserted, file, 'insert');
      continue;
    }
    addRow(rows, record, file, defaultOperation);
    const config = asRecord(record.config);
    if (config && Array.isArray(config.patches)) {
      rows.push(...collectRows(config.patches, file, 'replace'));
    }
  }
  return rows;
}

/** Parse Cordis configs with core scalars while preserving `!!js` as inert text. */
export async function parseCordisConfigs(rootDir: string): Promise<DshCordisAnalysis> {
  const matches = await glob(CORDIS_FILES, {
    cwd: rootDir,
    nodir: true,
    ignore: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/.git/**'],
  });
  const files = matches.sort();
  const rows: DshCordisRow[] = [];
  const parseErrors: Array<{ file: string; message: string }> = [];

  for (const file of files) {
    try {
      const path = join(rootDir, file);
      const info = await stat(path);
      if (info.size > MAX_SCANNABLE_FILE_BYTES) {
        parseErrors.push({ file, message: `Cordis file exceeds ${MAX_SCANNABLE_FILE_BYTES} byte scan limit` });
        continue;
      }
      const raw = await readFile(path, 'utf8');
      const document = parseDocument(raw, {
        schema: 'core',
        strict: true,
        customTags: [JS_EXPRESSION_TAG],
      });
      if (document.errors.length > 0) {
        parseErrors.push({ file, message: document.errors.map(error => error.message).join('; ') });
        continue;
      }
      rows.push(...collectRows(document.toJS(), file));
    } catch (error) {
      parseErrors.push({ file, message: (error as Error).message });
    }
  }

  return { files, rows, parseErrors };
}
