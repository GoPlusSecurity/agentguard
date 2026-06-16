import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

// Compiled location is dist/tests/mcpb-manifest.test.js, so the repo root is two
// levels up. This keeps the test independent of the cwd `npm test` runs from.
const repoRoot = path.resolve(__dirname, '..', '..');

const manifestPath = path.join(repoRoot, 'mcpb', 'manifest.json');
const iconPath = path.join(repoRoot, 'mcpb', 'icon.png');
const packagePath = path.join(repoRoot, 'package.json');
const buildScriptPath = path.join(repoRoot, 'scripts', 'build-mcpb.sh');

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
const buildScript = fs.readFileSync(buildScriptPath, 'utf8');

// Minimal PNG header reader: validates the signature and returns IHDR dimensions.
function readPngSize(buf: Buffer): { width: number; height: number } {
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.ok(buf.subarray(0, 8).equals(signature), 'icon.png must be a valid PNG');
  assert.equal(buf.subarray(12, 16).toString('ascii'), 'IHDR', 'PNG must start with IHDR chunk');
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
}

describe('mcpb/manifest.json — MCP Directory requirements', () => {
  it('declares manifest_version >= 0.3 (required for privacy_policies)', () => {
    assert.equal(typeof manifest.manifest_version, 'string');
    const [major, minor] = manifest.manifest_version.split('.').map(Number);
    assert.ok(major > 0 || minor >= 3, `manifest_version ${manifest.manifest_version} must be >= 0.3`);
  });

  it('references an icon file that exists and is a square PNG', () => {
    assert.equal(manifest.icon, 'icon.png', 'icon field must be "icon.png" (bundle root)');
    assert.ok(fs.existsSync(iconPath), 'mcpb/icon.png must exist');
    const { width, height } = readPngSize(fs.readFileSync(iconPath));
    assert.equal(width, height, `icon must be square, got ${width}x${height}`);
    assert.ok(width >= 256, `icon must be at least 256px, got ${width}px`);
  });

  it('declares a non-empty privacy_policies list of https URLs', () => {
    assert.ok(Array.isArray(manifest.privacy_policies), 'privacy_policies must be an array');
    assert.ok(manifest.privacy_policies.length > 0, 'privacy_policies must not be empty');
    for (const url of manifest.privacy_policies) {
      assert.match(url, /^https:\/\//, `privacy policy URL must be https: ${url}`);
      // Guard against pasting a tracking-redirect wrapper instead of the canonical policy.
      assert.doesNotMatch(url, /google\.com\/url\?/, `privacy policy must not be a redirect wrapper: ${url}`);
    }
  });

  it('keeps manifest version in sync with package.json', () => {
    assert.equal(manifest.version, pkg.version, 'manifest.version must match package.json version');
  });

  it('points the server entry at the compiled MCP server', () => {
    assert.equal(manifest.server?.type, 'node');
    assert.equal(manifest.server?.entry_point, 'server/dist/mcp-server.js');
    assert.equal(manifest.server?.mcp_config?.command, 'node');
  });

  it('lists tools, including the off-machine registry tools that triggered the privacy requirement', () => {
    assert.ok(Array.isArray(manifest.tools) && manifest.tools.length > 0, 'tools must be non-empty');
    for (const tool of manifest.tools) {
      assert.equal(typeof tool.name, 'string');
      assert.ok(tool.name.length > 0, 'each tool needs a name');
      assert.ok(typeof tool.description === 'string' && tool.description.length > 0, 'each tool needs a description');
    }
    const names = manifest.tools.map((t: { name: string }) => t.name);
    for (const required of ['registry_lookup', 'registry_attest', 'registry_revoke', 'registry_list']) {
      assert.ok(names.includes(required), `manifest must list ${required}`);
    }
  });
});

describe('scripts/build-mcpb.sh — bundle hygiene', () => {
  it('does not run package lifecycle scripts during the release build install', () => {
    assert.match(buildScript, /\bnpm ci --ignore-scripts\b/);
    assert.doesNotMatch(buildScript, /\bnpm ci\n/);
  });

  it('removes non-runtime TypeScript artifacts from the packaged server dist', () => {
    assert.match(buildScript, /rm -rf "\$STAGE\/server\/dist\/tests"/);
    assert.match(buildScript, /-name '\*\.map'/);
    assert.match(buildScript, /-name '\*\.d\.ts'/);
    assert.match(buildScript, /\^server\/dist\/tests\//);
    assert.match(buildScript, /\\\.map\|\\\.d\\\.ts/);
  });
});
