import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { discoverDshSelfCheckRoots } from '../feed/dsh-discovery.js';

function write(path: string, body: string): void {
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, body, 'utf8');
}

describe('feed/dsh-discovery', () => {
  it('discovers bounded DSH skills, profiles, direct dependencies, and Cordis patches', async () => {
    const root = mkdtempSync(join(tmpdir(), 'agentguard-dsh-discovery-'));
    const dshHome = join(root, 'dsh-home');
    const cwd = join(root, 'project');
    const homeSkills = join(dshHome, 'skills');
    const projectSkills = join(cwd, '.dsh', 'skills');
    mkdirSync(homeSkills, { recursive: true });
    mkdirSync(projectSkills, { recursive: true });

    const web = join(dshHome, 'profiles', 'web');
    const worker = join(dshHome, 'profiles', 'worker');
    write(join(web, 'package.json'), JSON.stringify({
      name: 'web-profile',
      dependencies: {
        'direct-plugin': '1.0.0',
        '@scope/direct-plugin': '2.0.0',
        '@goplus/agentguard': '1.1.29',
        'spoofed-agentguard': '1.0.0',
        '../escape': '3.0.0',
      },
      optionalDependencies: { 'optional-plugin': '1.0.0' },
    }));
    write(join(worker, 'package.json'), JSON.stringify({ name: 'worker-profile' }));
    for (const name of ['direct-plugin', 'optional-plugin', 'transitive-only', 'spoofed-agentguard']) {
      write(join(web, 'node_modules', name, 'package.json'), JSON.stringify({ name, version: '1.0.0' }));
    }
    write(join(web, 'node_modules', '@goplus', 'agentguard', 'package.json'), JSON.stringify({
      name: '@goplus/agentguard', version: '1.1.29',
    }));
    write(join(web, 'node_modules', 'spoofed-agentguard', 'package.json'), JSON.stringify({
      name: '@goplus/agentguard', version: '1.0.0',
    }));
    write(join(web, 'node_modules', '@scope', 'direct-plugin', 'package.json'), JSON.stringify({
      name: '@scope/direct-plugin', version: '2.0.0',
    }));
    write(join(dshHome, 'cordis.patch.yml'), '- insert: []\n');
    write(join(web, 'cordis.patch.yaml'), '- insert: []\n');
    const patchOnly = join(dshHome, 'profiles', 'patch-only', 'cordis.patch.yml');
    write(patchOnly, '- insert: []\n');

    const roots = await discoverDshSelfCheckRoots({ dshHome, cwd });

    assert.deepEqual(roots.skillRoots, [projectSkills, homeSkills].sort());
    assert.ok(roots.pluginRoots.includes(join(web, 'package.json')));
    assert.ok(roots.pluginRoots.includes(join(worker, 'package.json')));
    assert.ok(roots.pluginRoots.includes(join(web, 'node_modules', 'direct-plugin')));
    assert.ok(roots.pluginRoots.includes(join(web, 'node_modules', '@scope', 'direct-plugin')));
    assert.ok(roots.pluginRoots.includes(join(web, 'node_modules', 'optional-plugin')));
    assert.ok(roots.pluginRoots.includes(join(dshHome, 'cordis.patch.yml')));
    assert.ok(roots.pluginRoots.includes(join(web, 'cordis.patch.yaml')));
    assert.ok(roots.pluginRoots.includes(patchOnly));
    assert.ok(roots.supplyChainPaths.includes(join(web, 'package.json')));
    assert.ok(roots.supplyChainPaths.includes(join(web, 'node_modules', 'direct-plugin')));
    assert.ok(roots.urlScanPaths.includes(join(web, 'package.json')));
    assert.ok(roots.urlScanPaths.includes(join(dshHome, 'cordis.patch.yml')));
    assert.equal(roots.pluginRoots.some(path => path.includes('transitive-only')), false);
    assert.equal(roots.pluginRoots.some(path => path.includes('escape')), false);
    assert.deepEqual(roots.installedPluginDirs, [
      join(web, 'node_modules', '@scope', 'direct-plugin'),
      join(web, 'node_modules', 'direct-plugin'),
      join(web, 'node_modules', 'optional-plugin'),
      join(web, 'node_modules', 'spoofed-agentguard'),
    ].sort());
    assert.equal(roots.installedPluginDirs.includes(join(web, 'node_modules', '@goplus', 'agentguard')), false);
    assert.deepEqual(roots.pluginRoots, [...roots.pluginRoots].sort());
    assert.deepEqual(roots.installedPluginDirs, [...roots.installedPluginDirs].sort());
    assert.deepEqual(roots.supplyChainPaths, [...roots.supplyChainPaths].sort());
    assert.deepEqual(roots.urlScanPaths, [...roots.urlScanPaths].sort());
  });

  it('resolves DSH_HOME and cwd at call time', async () => {
    const first = mkdtempSync(join(tmpdir(), 'agentguard-dsh-discovery-first-'));
    const second = mkdtempSync(join(tmpdir(), 'agentguard-dsh-discovery-second-'));
    mkdirSync(join(first, 'skills'), { recursive: true });
    mkdirSync(join(second, 'skills'), { recursive: true });
    const previousHome = process.env.DSH_HOME;
    try {
      process.env.DSH_HOME = first;
      assert.deepEqual((await discoverDshSelfCheckRoots()).skillRoots, [join(first, 'skills')]);
      process.env.DSH_HOME = second;
      assert.deepEqual((await discoverDshSelfCheckRoots()).skillRoots, [join(second, 'skills')]);
    } finally {
      if (previousHome === undefined) delete process.env.DSH_HOME;
      else process.env.DSH_HOME = previousHome;
    }
  });
});
