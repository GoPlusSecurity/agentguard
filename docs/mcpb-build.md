# Building the `.mcpb` bundle

AgentGuard ships to the Anthropic **MCP / Desktop Extensions Directory** as an
`.mcpb` bundle (an MCP Bundle / Desktop Extension — a zip containing a
`manifest.json`, an `icon.png`, and the Node server with its production
dependencies).

The bundle is built reproducibly from this repo. Nothing is assembled by hand.

## Source files

| Path | Purpose |
| --- | --- |
| `mcpb/manifest.json` | The bundle manifest (`manifest_version` `0.3`, `icon`, `privacy_policies`, tool list). The `version` is stamped from `package.json` at build time. |
| `mcpb/icon.png` | 512×512 square icon shown in the directory. |
| `scripts/build-mcpb.sh` | Assembles the staging tree and packs the `.mcpb`. |

## Build locally

```bash
npm run build:mcpb
```

This compiles TypeScript, stages `server/` with production-only
`node_modules`, copies the manifest and icon to the bundle root, and packs the
result with the official [`@anthropic-ai/mcpb`](https://www.npmjs.com/package/@anthropic-ai/mcpb)
CLI. Output lands at:

```
dist-mcpb/agentguard.mcpb
```

Verify the manifest of a built bundle:

```bash
unzip -p dist-mcpb/agentguard.mcpb manifest.json \
  | jq '{manifest_version, icon, privacy_policies, version}'
```

## Publishing a release

Pushing a `v*` tag runs `.github/workflows/release-mcpb.yml`, which builds the
bundle and attaches it to the matching GitHub Release as `agentguard.mcpb`.
Publishing the `.mcpb` under a stable asset filename lets the MCP Directory pick
up new versions automatically.

```bash
npm version patch        # bumps package.json, creates the tag
git push --follow-tags
```
