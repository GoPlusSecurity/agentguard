import { readFile } from 'node:fs/promises';
import { basename, join } from 'node:path';
import { glob } from 'glob';
import {
  isMap,
  isNode,
  isPair,
  isScalar,
  isSeq,
  parseDocument,
  type ScalarTag,
  type YAMLMap,
} from 'yaml';
import type { DshCordisAnalysis, DshCordisRow } from './types.js';
import { MAX_SCANNABLE_FILE_BYTES } from '../scanner/file-walker.js';
import { inspectRegularFileWithinRoot } from '../scanner/safe-file.js';

const CORDIS_FILES = ['**/cordis.yml', '**/cordis.yaml', '**/cordis.patch.yml', '**/cordis.patch.yaml'];
const MAX_CORDIS_AST_DEPTH = 64;
const MAX_CORDIS_AST_NODES = 20_000;
const JS_EXPRESSION_TAG: ScalarTag = {
  tag: 'tag:yaml.org,2002:js',
  resolve: value => value,
};

function mapValue(map: YAMLMap, key: string): unknown {
  return map.get(key, true) as unknown;
}

function scalarValue(map: YAMLMap, key: string): unknown {
  const value = mapValue(map, key);
  return isScalar(value) ? value.value : undefined;
}

function validateAstLimits(root: unknown): void {
  if (!isNode(root)) return;
  const stack: Array<{ node: unknown; depth: number }> = [{ node: root, depth: 1 }];
  let visited = 0;
  while (stack.length > 0) {
    const current = stack.pop()!;
    visited += 1;
    if (visited > MAX_CORDIS_AST_NODES) {
      throw new Error(`Cordis YAML exceeds ${MAX_CORDIS_AST_NODES} node limit`);
    }
    if (current.depth > MAX_CORDIS_AST_DEPTH) {
      throw new Error(`Cordis YAML exceeds ${MAX_CORDIS_AST_DEPTH} level depth limit`);
    }
    if (isMap(current.node) || isSeq(current.node)) {
      for (const item of current.node.items) {
        if (isPair(item)) {
          if (isNode(item.key)) stack.push({ node: item.key, depth: current.depth + 1 });
          if (isNode(item.value)) stack.push({ node: item.value, depth: current.depth + 1 });
        } else if (isNode(item)) {
          stack.push({ node: item, depth: current.depth + 1 });
        }
      }
    }
  }
}

function addRow(rows: DshCordisRow[], row: YAMLMap, file: string, operation: DshCordisRow['operation']): void {
  const id = scalarValue(row, 'id');
  const name = scalarValue(row, 'name');
  const disabled = scalarValue(row, 'disabled');
  rows.push({
    file,
    id: typeof id === 'string' ? id : undefined,
    name: typeof name === 'string' ? name : undefined,
    operation,
    hasConfig: row.has('config'),
    disabled: disabled === true || typeof disabled === 'string',
  });
}

function collectRows(
  value: unknown,
  file: string,
  defaultOperation: 'entry' | 'replace' = basename(file).includes('.patch.') ? 'replace' : 'entry',
  context = 'document root',
): DshCordisRow[] {
  const rows: DshCordisRow[] = [];
  if (!isSeq(value)) throw new Error(`Expected a Cordis row sequence at ${context}`);
  for (const [index, item] of value.items.entries()) {
    if (!isMap(item)) throw new Error(`Expected a Cordis row mapping at ${context}[${index}]`);
    const insertedRows = mapValue(item, 'insert');
    if (insertedRows !== undefined) {
      if (!isSeq(insertedRows)) throw new Error(`Expected insert to be a sequence at ${context}[${index}]`);
      for (const [insertIndex, inserted] of insertedRows.items.entries()) {
        if (!isMap(inserted)) {
          throw new Error(`Expected an inserted Cordis row mapping at ${context}[${index}].insert[${insertIndex}]`);
        }
        addRow(rows, inserted, file, 'insert');
      }
      continue;
    }
    addRow(rows, item, file, defaultOperation);
    const config = mapValue(item, 'config');
    if (isMap(config)) {
      const patches = mapValue(config, 'patches');
      if (patches !== undefined) {
        rows.push(...collectRows(patches, file, 'replace', `${context}[${index}].config.patches`));
      }
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
      const safeFile = await inspectRegularFileWithinRoot(rootDir, path);
      if (safeFile.size > MAX_SCANNABLE_FILE_BYTES) {
        parseErrors.push({ file, message: `Cordis file exceeds ${MAX_SCANNABLE_FILE_BYTES} byte scan limit` });
        continue;
      }
      const raw = await readFile(safeFile.path, 'utf8');
      const document = parseDocument(raw, {
        schema: 'core',
        strict: true,
        customTags: [JS_EXPRESSION_TAG],
      });
      if (document.errors.length > 0) {
        parseErrors.push({ file, message: document.errors.map(error => error.message).join('; ') });
        continue;
      }
      validateAstLimits(document.contents);
      rows.push(...collectRows(document.contents, file));
    } catch (error) {
      parseErrors.push({ file, message: (error as Error).message });
    }
  }

  return { files, rows, parseErrors };
}
