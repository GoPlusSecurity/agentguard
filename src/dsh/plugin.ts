import { scanDshPlugin } from './scan.js';
import { renderDshMarkdown } from '../reports/dsh-report.js';

export const name = 'agentguard-dsh-plugin';
export const inject = ['tools'];

type ToolDefinition = {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  output: {
    schema: Record<string, unknown>;
    render: (args: unknown, value: AgentGuardDshToolResult) => Array<{ type: 'text'; text: string }>;
  };
  timeoutMs: number;
  execute: (args: AgentGuardDshToolArgs) => Promise<AgentGuardDshToolResult>;
};

type DshPluginContext = {
  tools: {
    register: (tool: ToolDefinition) => unknown;
  };
};

export type AgentGuardDshToolArgs = {
  target: string;
  format?: 'markdown' | 'json';
};

export type AgentGuardDshToolResult = {
  riskLevel: string;
  installRecommendation: string;
  format: 'markdown' | 'json';
  content: string;
};

export function createAgentGuardDshTool(): ToolDefinition {
  return {
    name: 'agentguard_dsh_scan',
    description:
      'Statically scan a local DeepSeek Harness plugin directory or HTTPS GitHub repository with AgentGuard. ' +
      'Returns explainable risk findings and an installation recommendation without installing or executing the target.',
    parameters: {
      type: 'object',
      properties: {
        target: {
          type: 'string',
          description: 'Absolute or workspace-relative local directory, or an HTTPS GitHub repository URL.',
        },
        format: {
          type: 'string',
          enum: ['markdown', 'json'],
          description: 'Report format. Defaults to markdown.',
        },
      },
      required: ['target'],
      additionalProperties: false,
    },
    output: {
      schema: {
        type: 'object',
        properties: {
          riskLevel: { type: 'string' },
          installRecommendation: { type: 'string' },
          format: { type: 'string', enum: ['markdown', 'json'] },
          content: { type: 'string' },
        },
        required: ['riskLevel', 'installRecommendation', 'format', 'content'],
        additionalProperties: false,
      },
      render: (_args, value) => [{ type: 'text', text: value.content }],
    },
    timeoutMs: 120_000,
    async execute(args) {
      if (!args || typeof args.target !== 'string' || args.target.trim() === '') {
        throw new Error('target must be a non-empty local directory or HTTPS GitHub repository URL');
      }
      if (args.format !== undefined && args.format !== 'markdown' && args.format !== 'json') {
        throw new Error('format must be markdown or json');
      }

      const report = await scanDshPlugin(args.target.trim());
      const format = args.format ?? 'markdown';
      return {
        riskLevel: report.riskLevel,
        installRecommendation: report.installRecommendation,
        format,
        content: format === 'json' ? JSON.stringify(report, null, 2) : renderDshMarkdown(report),
      };
    },
  };
}

export function apply(ctx: DshPluginContext): void {
  ctx.tools.register(createAgentGuardDshTool());
}
