#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { z } from 'zod';
import { Command } from 'commander';

import { SkillScanner } from './scanner/index.js';
import { SkillRegistry } from './registry/index.js';
import { ActionScanner } from './action/index.js';
import type { SkillIdentity, CapabilityModel } from './types/skill.js';
import type { ActionEnvelope, Web3Intent } from './types/action.js';
import type { TrustLevel } from './types/registry.js';

// Module instances (initialized in createServer)
let scanner: SkillScanner;
let registry: SkillRegistry;
let actionScanner: ActionScanner;

// Zod schemas for validation
const SkillIdentitySchema = z.object({
  id: z.string(),
  source: z.string(),
  version_ref: z.string(),
  artifact_hash: z.string(),
});

const CapabilityModelSchema = z.object({
  network_allowlist: z.array(z.string()),
  filesystem_allowlist: z.array(z.string()),
  exec: z.enum(['allow', 'deny']),
  secrets_allowlist: z.array(z.string()),
  web3: z.object({
    chains_allowlist: z.array(z.number()),
    rpc_allowlist: z.array(z.string()),
    tx_policy: z.enum(['allow', 'confirm_high_risk', 'deny']),
  }).optional(),
});

/**
 * Create and configure the MCP server
 */
function createServer(options?: { registryPath?: string }): Server {
  scanner = new SkillScanner();
  registry = new SkillRegistry({ filePath: options?.registryPath });
  actionScanner = new ActionScanner({ registry });

  const server = new Server(
    {
      name: 'agentguard',
      version: '1.0.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // List all available tools
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        // Scanner tools
        {
          name: 'skill_scanner_scan',
          description: 'Scan a skill directory for security risks. Returns risk level, tags, and evidence.',
          inputSchema: {
            type: 'object',
            properties: {
              skill: {
                type: 'object',
                properties: {
                  id: { type: 'string', description: 'Skill identifier' },
                  source: { type: 'string', description: 'Source repository' },
                  version_ref: { type: 'string', description: 'Version reference' },
                  artifact_hash: { type: 'string', description: 'Artifact hash' },
                },
                required: ['id', 'source', 'version_ref', 'artifact_hash'],
              },
              path: { type: 'string', description: 'Path to skill directory' },
              deep: { type: 'boolean', description: 'Enable deep analysis', default: false },
            },
            required: ['skill', 'path'],
          },
        },

        // Registry tools
        {
          name: 'registry_lookup',
          description: 'Look up a skill\'s trust record in the registry.',
          inputSchema: {
            type: 'object',
            properties: {
              skill: {
                type: 'object',
                properties: {
                  id: { type: 'string' },
                  source: { type: 'string' },
                  version_ref: { type: 'string' },
                  artifact_hash: { type: 'string' },
                },
                required: ['id', 'source', 'version_ref', 'artifact_hash'],
              },
            },
            required: ['skill'],
          },
        },
        {
          name: 'registry_attest',
          description: 'Add or update a skill\'s trust record. May require confirmation for upgrades.',
          inputSchema: {
            type: 'object',
            properties: {
              skill: {
                type: 'object',
                properties: {
                  id: { type: 'string' },
                  source: { type: 'string' },
                  version_ref: { type: 'string' },
                  artifact_hash: { type: 'string' },
                },
                required: ['id', 'source', 'version_ref', 'artifact_hash'],
              },
              trust_level: {
                type: 'string',
                enum: ['untrusted', 'restricted', 'trusted'],
              },
              capabilities: {
                type: 'object',
                properties: {
                  network_allowlist: { type: 'array', items: { type: 'string' } },
                  filesystem_allowlist: { type: 'array', items: { type: 'string' } },
                  exec: { type: 'string', enum: ['allow', 'deny'] },
                  secrets_allowlist: { type: 'array', items: { type: 'string' } },
                },
                required: ['network_allowlist', 'filesystem_allowlist', 'exec', 'secrets_allowlist'],
              },
              reviewed_by: { type: 'string', description: 'Reviewer identifier' },
              notes: { type: 'string', description: 'Review notes' },
              expires_at: { type: 'string', description: 'Expiration date (ISO 8601)' },
              force: { type: 'boolean', description: 'Force attest without confirmation', default: false },
            },
            required: ['skill', 'trust_level', 'capabilities', 'reviewed_by', 'notes'],
          },
        },
        {
          name: 'registry_revoke',
          description: 'Revoke trust for skills matching the criteria.',
          inputSchema: {
            type: 'object',
            properties: {
              source: { type: 'string', description: 'Source pattern (supports wildcards)' },
              version_ref: { type: 'string', description: 'Version to revoke' },
              record_key: { type: 'string', description: 'Specific record key' },
              reason: { type: 'string', description: 'Revocation reason' },
            },
            required: ['reason'],
          },
        },
        {
          name: 'registry_list',
          description: 'List trust records with optional filters.',
          inputSchema: {
            type: 'object',
            properties: {
              trust_level: { type: 'string', enum: ['untrusted', 'restricted', 'trusted'] },
              status: { type: 'string', enum: ['active', 'revoked'] },
              source_pattern: { type: 'string', description: 'Filter by source pattern' },
              include_expired: { type: 'boolean', default: false },
            },
          },
        },

        // Action scanner tools
        {
          name: 'action_scanner_decide',
          description: 'Evaluate a runtime action and return allow/deny/confirm decision.',
          inputSchema: {
            type: 'object',
            properties: {
              actor: {
                type: 'object',
                properties: {
                  skill: {
                    type: 'object',
                    properties: {
                      id: { type: 'string' },
                      source: { type: 'string' },
                      version_ref: { type: 'string' },
                      artifact_hash: { type: 'string' },
                    },
                    required: ['id', 'source', 'version_ref', 'artifact_hash'],
                  },
                },
                required: ['skill'],
              },
              action: {
                type: 'object',
                properties: {
                  type: {
                    type: 'string',
                    enum: ['network_request', 'exec_command', 'read_file', 'write_file', 'secret_access', 'web3_tx', 'web3_sign'],
                  },
                  data: { type: 'object', description: 'Action-specific data' },
                },
                required: ['type', 'data'],
              },
              context: {
                type: 'object',
                properties: {
                  session_id: { type: 'string' },
                  user_present: { type: 'boolean' },
                  env: { type: 'string', enum: ['prod', 'dev', 'test'] },
                },
                required: ['session_id', 'user_present', 'env'],
              },
            },
            required: ['actor', 'action', 'context'],
          },
        },
        {
          name: 'action_scanner_simulate_web3',
          description: 'Simulate a Web3 transaction using GoPlus API. Returns risk analysis.',
          inputSchema: {
            type: 'object',
            properties: {
              chain_id: { type: 'number', description: 'Chain ID (e.g., 1 for Ethereum)' },
              from: { type: 'string', description: 'Sender address' },
              to: { type: 'string', description: 'Target address' },
              value: { type: 'string', description: 'Value in wei' },
              data: { type: 'string', description: 'Transaction calldata' },
              origin: { type: 'string', description: 'DApp origin URL' },
            },
            required: ['chain_id', 'from', 'to', 'value'],
          },
        },
      ],
    };
  });

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      switch (name) {
        // Scanner: scan
        case 'skill_scanner_scan': {
          const skill = SkillIdentitySchema.parse(args?.skill);
          const path = args?.path as string;
          const deep = args?.deep as boolean || false;

          const result = await scanner.scan({
            skill,
            payload: { type: 'dir', ref: path },
            options: { deep },
          });

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result, null, 2),
              },
            ],
          };
        }

        // Registry: lookup
        case 'registry_lookup': {
          const skill = SkillIdentitySchema.parse(args?.skill);
          const result = await registry.lookup(skill);

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result, null, 2),
              },
            ],
          };
        }

        // Registry: attest
        case 'registry_attest': {
          const skill = SkillIdentitySchema.parse(args?.skill);
          const trustLevel = args?.trust_level as TrustLevel;
          const capabilities = CapabilityModelSchema.parse(args?.capabilities);
          const reviewedBy = args?.reviewed_by as string;
          const notes = args?.notes as string;
          const expiresAt = args?.expires_at as string | undefined;
          const force = args?.force as boolean || false;

          const attestFn = force ? registry.forceAttest.bind(registry) : registry.attest.bind(registry);

          const result = await attestFn({
            skill,
            trust_level: trustLevel,
            capabilities,
            expires_at: expiresAt,
            review: {
              reviewed_by: reviewedBy,
              evidence_refs: [],
              notes,
            },
          });

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result, null, 2),
              },
            ],
          };
        }

        // Registry: revoke
        case 'registry_revoke': {
          const source = args?.source as string | undefined;
          const versionRef = args?.version_ref as string | undefined;
          const recordKey = args?.record_key as string | undefined;
          const reason = args?.reason as string;

          const count = await registry.revoke(
            { source, version_ref: versionRef, record_key: recordKey },
            reason
          );

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({ revoked_count: count }, null, 2),
              },
            ],
          };
        }

        // Registry: list
        case 'registry_list': {
          const filters = {
            trust_level: args?.trust_level as TrustLevel | undefined,
            status: args?.status as 'active' | 'revoked' | undefined,
            source_pattern: args?.source_pattern as string | undefined,
            include_expired: args?.include_expired as boolean || false,
          };

          const records = await registry.list(filters);

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify({ count: records.length, records }, null, 2),
              },
            ],
          };
        }

        // Action scanner: decide
        case 'action_scanner_decide': {
          const envelope = args as unknown as ActionEnvelope;
          envelope.context.time = new Date().toISOString();

          const result = await actionScanner.decide(envelope);

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result, null, 2),
              },
            ],
          };
        }

        // Action scanner: simulate_web3
        case 'action_scanner_simulate_web3': {
          const intent: Web3Intent = {
            chain_id: args?.chain_id as number,
            from: args?.from as string,
            to: args?.to as string,
            value: args?.value as string,
            data: args?.data as string | undefined,
            origin: args?.origin as string | undefined,
            kind: 'tx',
          };

          const result = await actionScanner.simulateWeb3(intent);

          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(result, null, 2),
              },
            ],
          };
        }

        default:
          throw new Error(`Unknown tool: ${name}`);
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ error: errorMessage }),
          },
        ],
        isError: true,
      };
    }
  });

  return server;
}

/**
 * Main entry point
 */
async function main() {
  const program = new Command();

  program
    .name('agentguard')
    .description('Security skill MCP server for AI agents')
    .version('1.0.0')
    .option('--registry-path <path>', 'Path to registry file')
    .action(async (options) => {
      // Create server
      const server = createServer({
        registryPath: options.registryPath,
      });

      // Connect via stdio
      const transport = new StdioServerTransport();
      await server.connect(transport);

      console.error('GoPlus AgentGuard MCP server started');
    });

  await program.parseAsync(process.argv);
}

// Run if executed directly
main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
