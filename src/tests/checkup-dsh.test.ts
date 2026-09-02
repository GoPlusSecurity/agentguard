import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { scanDshPluginsForCheckup } from '../checkup/dsh.js';

describe('checkup DSH plugin scanning', () => {
  it('reports a failed plugin scan without aborting the checkup batch', async () => {
    const missingPlugin = join(mkdtempSync(join(tmpdir(), 'agentguard-checkup-dsh-')), 'missing-plugin');

    const result = await scanDshPluginsForCheckup([missingPlugin]);

    assert.equal(result.pluginsScanned, 0);
    assert.equal(result.scoreDeduction, 8);
    assert.deepEqual(result.findings, [{
      severity: 'HIGH',
      text: `missing-plugin: DSH plugin scan failed: Local scan directory not found: ${missingPlugin}`,
    }]);
  });
});
