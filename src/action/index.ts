import type {
  ActionEnvelope,
  PolicyDecision,
  ActionEvidence,
  Web3Intent,
  Web3SimulationResult,
  NetworkRequestData,
  ExecCommandData,
  Web3TxData,
  Web3SignData,
  Decision,
} from '../types/action.js';
import type { RiskLevel } from '../types/scanner.js';
import type { CapabilityModel } from '../types/skill.js';
import { DEFAULT_CAPABILITY } from '../types/skill.js';
import { SkillRegistry } from '../registry/index.js';
import { analyzeNetworkRequest } from './detectors/network.js';
import { analyzeExecCommand } from './detectors/exec.js';
import { detectSecretLeak, containsCriticalSecrets } from './detectors/secret-leak.js';
import { GoPlusClient, goplusClient } from './goplus/client.js';
import { extractDomain } from '../utils/patterns.js';

/**
 * Action Scanner options
 */
export interface ActionScannerOptions {
  /** Registry instance */
  registry?: SkillRegistry;
  /** GoPlus client */
  goplusClient?: GoPlusClient;
  /** Default capabilities when no registry record found */
  defaultCapabilities?: CapabilityModel;
}

/**
 * Action Scanner - Module C
 * Runtime action decision engine
 */
export class ActionScanner {
  private registry: SkillRegistry;
  private goplus: GoPlusClient;
  private defaultCapabilities: CapabilityModel;

  constructor(options: ActionScannerOptions = {}) {
    this.registry = options.registry || new SkillRegistry();
    this.goplus = options.goplusClient || goplusClient;
    this.defaultCapabilities = options.defaultCapabilities || DEFAULT_CAPABILITY;
  }

  /**
   * Main decision method
   */
  async decide(envelope: ActionEnvelope): Promise<PolicyDecision> {
    const { actor, action, context } = envelope;

    // Look up skill capabilities
    const lookupResult = await this.registry.lookup(actor.skill);
    const capabilities = lookupResult.effective_capabilities;
    const trustLevel = lookupResult.effective_trust_level;

    // Route to appropriate handler based on action type
    switch (action.type) {
      case 'network_request':
        return this.handleNetworkRequest(
          action.data as NetworkRequestData,
          capabilities,
          context.user_present
        );

      case 'exec_command':
        return this.handleExecCommand(
          action.data as ExecCommandData,
          capabilities
        );

      case 'web3_tx':
        return this.handleWeb3Tx(
          action.data as Web3TxData,
          capabilities,
          context.user_present
        );

      case 'web3_sign':
        return this.handleWeb3Sign(
          action.data as Web3SignData,
          capabilities,
          context.user_present
        );

      case 'secret_access':
        return this.handleSecretAccess(
          action.data as { secret_name: string; access_type: string },
          capabilities
        );

      case 'read_file':
      case 'write_file':
        return this.handleFileOperation(
          action.data as { path: string },
          action.type,
          capabilities
        );

      default:
        return {
          decision: 'deny',
          risk_level: 'high',
          risk_tags: ['UNKNOWN_ACTION_TYPE'],
          evidence: [
            {
              type: 'unknown_action',
              description: `Unknown action type: ${action.type}`,
            },
          ],
          explanation: `Unknown action type: ${action.type}`,
        };
    }
  }

  /**
   * Handle network request actions
   */
  private async handleNetworkRequest(
    request: NetworkRequestData,
    capabilities: CapabilityModel,
    userPresent: boolean
  ): Promise<PolicyDecision> {
    const analysis = analyzeNetworkRequest(
      request,
      capabilities.network_allowlist
    );

    // Critical secret leak - always deny
    if (analysis.risk_tags.includes('CRITICAL_SECRET_EXFIL')) {
      return {
        decision: 'deny',
        risk_level: 'critical',
        risk_tags: analysis.risk_tags,
        evidence: analysis.evidence,
        explanation: analysis.block_reason || 'Critical secret exfiltration blocked',
      };
    }

    // Should block
    if (analysis.should_block) {
      return {
        decision: 'deny',
        risk_level: analysis.risk_level,
        risk_tags: analysis.risk_tags,
        evidence: analysis.evidence,
        explanation: analysis.block_reason || 'Request blocked',
      };
    }

    // High risk - require confirmation
    if (analysis.risk_level === 'high' || analysis.risk_level === 'critical') {
      return {
        decision: userPresent ? 'confirm' : 'deny',
        risk_level: analysis.risk_level,
        risk_tags: analysis.risk_tags,
        evidence: analysis.evidence,
        explanation: userPresent
          ? 'High-risk request requires confirmation'
          : 'High-risk request denied (user not present)',
      };
    }

    // Untrusted domain - require confirmation
    if (analysis.risk_tags.includes('UNTRUSTED_DOMAIN')) {
      return {
        decision: userPresent ? 'confirm' : 'deny',
        risk_level: analysis.risk_level,
        risk_tags: analysis.risk_tags,
        evidence: analysis.evidence,
        explanation: userPresent
          ? 'Request to untrusted domain requires confirmation'
          : 'Request to untrusted domain denied (user not present)',
      };
    }

    // Allow
    return {
      decision: 'allow',
      risk_level: analysis.risk_level,
      risk_tags: analysis.risk_tags,
      evidence: analysis.evidence,
    };
  }

  /**
   * Handle command execution actions
   */
  private handleExecCommand(
    command: ExecCommandData,
    capabilities: CapabilityModel
  ): PolicyDecision {
    const execAllowed = capabilities.exec === 'allow';
    const analysis = analyzeExecCommand(command, execAllowed);

    if (analysis.should_block) {
      return {
        decision: 'deny',
        risk_level: analysis.risk_level,
        risk_tags: analysis.risk_tags,
        evidence: analysis.evidence,
        explanation: analysis.block_reason || 'Command execution blocked',
      };
    }

    // High-risk commands need confirmation even if exec is allowed
    if (analysis.risk_level === 'high' || analysis.risk_level === 'critical') {
      return {
        decision: 'confirm',
        risk_level: analysis.risk_level,
        risk_tags: analysis.risk_tags,
        evidence: analysis.evidence,
        explanation: 'High-risk command requires confirmation',
      };
    }

    return {
      decision: 'allow',
      risk_level: analysis.risk_level,
      risk_tags: analysis.risk_tags,
      evidence: analysis.evidence,
    };
  }

  /**
   * Handle Web3 transaction actions
   */
  private async handleWeb3Tx(
    tx: Web3TxData,
    capabilities: CapabilityModel,
    userPresent: boolean
  ): Promise<PolicyDecision> {
    const evidence: ActionEvidence[] = [];
    const riskTags: string[] = [];
    let riskLevel: RiskLevel = 'low';
    let decision: Decision = 'allow';

    // Check if chain is allowed
    if (capabilities.web3) {
      if (!capabilities.web3.chains_allowlist.includes(tx.chain_id)) {
        evidence.push({
          type: 'chain_not_allowed',
          description: `Chain ${tx.chain_id} not in allowlist`,
        });
        riskTags.push('CHAIN_NOT_ALLOWED');
        riskLevel = 'high';
        decision = 'deny';
      }
    }

    // Check origin for phishing
    if (tx.origin) {
      try {
        const phishingResult = await this.goplus.phishingSite(tx.origin);
        if (phishingResult.is_phishing || phishingResult.phishing_site) {
          evidence.push({
            type: 'phishing_origin',
            field: 'origin',
            match: tx.origin,
            description: 'Transaction origin is a known phishing site',
          });
          riskTags.push('PHISHING_ORIGIN');
          riskLevel = 'critical';
          decision = 'deny';
        }
      } catch (err) {
        // Phishing check failed, continue with other checks
      }
    }

    // Check target address
    try {
      const addressResult = await this.goplus.addressSecurity(
        tx.chain_id.toString(),
        [tx.to]
      );
      const addressRisk = addressResult[tx.to.toLowerCase()];

      if (addressRisk) {
        if (
          addressRisk.is_blacklisted ||
          addressRisk.is_phishing_activities ||
          addressRisk.is_stealing_attack
        ) {
          evidence.push({
            type: 'malicious_address',
            field: 'to',
            match: tx.to,
            description: 'Target address is flagged as malicious',
          });
          riskTags.push('MALICIOUS_ADDRESS');
          riskLevel = 'critical';
          decision = 'deny';
        }

        if (addressRisk.is_honeypot_related_address) {
          evidence.push({
            type: 'honeypot_related',
            field: 'to',
            match: tx.to,
            description: 'Target address is honeypot-related',
          });
          riskTags.push('HONEYPOT_RELATED');
          if (riskLevel !== 'critical') riskLevel = 'high';
        }
      }
    } catch (err) {
      // Address check failed, continue
    }

    // Simulate transaction if GoPlus is configured
    if (GoPlusClient.isConfigured() && decision !== 'deny') {
      try {
        const simulation = await this.goplus.simulateTransaction({
          chain_id: tx.chain_id.toString(),
          from: tx.from,
          to: tx.to,
          value: tx.value,
          data: tx.data,
        });

        // Check for unlimited approvals
        const unlimitedApprovals = simulation.approval_changes.filter(
          (a) => a.is_unlimited
        );

        if (unlimitedApprovals.length > 0) {
          evidence.push({
            type: 'unlimited_approval',
            description: `Unlimited approval to ${unlimitedApprovals.map((a) => a.spender).join(', ')}`,
          });
          riskTags.push('UNLIMITED_APPROVAL');
          if (riskLevel !== 'critical') riskLevel = 'high';
          if (decision === 'allow') decision = 'confirm';
        }

        // Add simulation risk tags
        riskTags.push(...simulation.risk_tags);

        if (!simulation.success) {
          evidence.push({
            type: 'simulation_failed',
            description: simulation.error_message || 'Transaction simulation failed',
          });
          riskTags.push('SIMULATION_FAILED');
          if (riskLevel === 'low') riskLevel = 'medium';
        }
      } catch (err) {
        // Simulation failed, continue with conservative approach
        evidence.push({
          type: 'simulation_error',
          description: 'Could not simulate transaction',
        });
      }
    }

    // Apply tx_policy
    if (capabilities.web3) {
      if (capabilities.web3.tx_policy === 'deny') {
        decision = 'deny';
      } else if (
        capabilities.web3.tx_policy === 'confirm_high_risk' &&
        riskLevel !== 'low'
      ) {
        if (decision === 'allow') decision = 'confirm';
      }
    }

    // User not present - upgrade confirm to deny
    if (!userPresent && decision === 'confirm') {
      decision = 'deny';
      evidence.push({
        type: 'user_not_present',
        description: 'Risky transaction denied because user is not present',
      });
    }

    return {
      decision,
      risk_level: riskLevel,
      risk_tags: riskTags,
      evidence,
      explanation:
        decision === 'deny'
          ? 'Transaction blocked due to security risks'
          : decision === 'confirm'
          ? 'Transaction requires user confirmation'
          : 'Transaction allowed',
    };
  }

  /**
   * Handle Web3 sign actions
   */
  private async handleWeb3Sign(
    sign: Web3SignData,
    capabilities: CapabilityModel,
    userPresent: boolean
  ): Promise<PolicyDecision> {
    const evidence: ActionEvidence[] = [];
    const riskTags: string[] = [];
    let riskLevel: RiskLevel = 'low';
    let decision: Decision = 'allow';

    // Check if chain is allowed
    if (capabilities.web3) {
      if (!capabilities.web3.chains_allowlist.includes(sign.chain_id)) {
        evidence.push({
          type: 'chain_not_allowed',
          description: `Chain ${sign.chain_id} not in allowlist`,
        });
        riskTags.push('CHAIN_NOT_ALLOWED');
        riskLevel = 'high';
        decision = 'deny';
      }
    }

    // Check origin for phishing
    if (sign.origin) {
      try {
        const phishingResult = await this.goplus.phishingSite(sign.origin);
        if (phishingResult.is_phishing || phishingResult.phishing_site) {
          evidence.push({
            type: 'phishing_origin',
            field: 'origin',
            match: sign.origin,
            description: 'Signature request origin is a known phishing site',
          });
          riskTags.push('PHISHING_ORIGIN');
          riskLevel = 'critical';
          decision = 'deny';
        }
      } catch (err) {
        // Continue
      }
    }

    // Check typed data for permit signatures
    if (sign.typed_data) {
      const typedDataStr = JSON.stringify(sign.typed_data);

      // Check for Permit/Permit2 signatures
      if (
        typedDataStr.includes('Permit') ||
        typedDataStr.includes('permit')
      ) {
        evidence.push({
          type: 'permit_signature',
          description: 'Permit signature detected - can grant token approvals',
        });
        riskTags.push('PERMIT_SIGNATURE');
        if (riskLevel === 'low') riskLevel = 'medium';
        if (decision === 'allow') decision = 'confirm';
      }

      // Check for unlimited values
      if (
        typedDataStr.includes('ffffffff') ||
        typedDataStr.includes('max') ||
        /value.*:.*['"]\d{30,}['"]/.test(typedDataStr)
      ) {
        evidence.push({
          type: 'unlimited_value',
          description: 'Signature contains unlimited/max value',
        });
        riskTags.push('UNLIMITED_VALUE');
        if (riskLevel !== 'critical') riskLevel = 'high';
        if (decision === 'allow') decision = 'confirm';
      }
    }

    // Check message for sensitive data
    if (sign.message) {
      if (containsCriticalSecrets(sign.message)) {
        evidence.push({
          type: 'secret_in_message',
          description: 'Message to sign contains sensitive data',
        });
        riskTags.push('SECRET_IN_SIGNATURE');
        riskLevel = 'critical';
        decision = 'deny';
      }
    }

    // User not present - upgrade confirm to deny
    if (!userPresent && decision === 'confirm') {
      decision = 'deny';
      evidence.push({
        type: 'user_not_present',
        description: 'Risky signature denied because user is not present',
      });
    }

    return {
      decision,
      risk_level: riskLevel,
      risk_tags: riskTags,
      evidence,
      explanation:
        decision === 'deny'
          ? 'Signature request blocked due to security risks'
          : decision === 'confirm'
          ? 'Signature request requires user confirmation'
          : 'Signature request allowed',
    };
  }

  /**
   * Handle secret access
   */
  private handleSecretAccess(
    access: { secret_name: string; access_type: string },
    capabilities: CapabilityModel
  ): PolicyDecision {
    const isAllowed = capabilities.secrets_allowlist.includes(access.secret_name);

    if (isAllowed) {
      return {
        decision: 'allow',
        risk_level: 'low',
        risk_tags: [],
        evidence: [],
      };
    }

    return {
      decision: 'deny',
      risk_level: 'high',
      risk_tags: ['SECRET_NOT_ALLOWED'],
      evidence: [
        {
          type: 'secret_access_denied',
          field: 'secret_name',
          match: access.secret_name,
          description: `Secret ${access.secret_name} not in allowlist`,
        },
      ],
      explanation: `Access to secret '${access.secret_name}' is not allowed`,
    };
  }

  /**
   * Handle file operations
   */
  private handleFileOperation(
    file: { path: string },
    type: 'read_file' | 'write_file',
    capabilities: CapabilityModel
  ): PolicyDecision {
    // Check if path is in allowlist
    const isAllowed = capabilities.filesystem_allowlist.some((pattern) => {
      if (pattern === '*') return true;
      if (pattern.endsWith('/**')) {
        const prefix = pattern.slice(0, -3);
        return file.path.startsWith(prefix);
      }
      if (pattern.endsWith('/*')) {
        const prefix = pattern.slice(0, -2);
        const remainder = file.path.slice(prefix.length);
        return file.path.startsWith(prefix) && !remainder.includes('/');
      }
      return file.path === pattern || file.path.startsWith(pattern + '/');
    });

    if (isAllowed) {
      return {
        decision: 'allow',
        risk_level: 'low',
        risk_tags: [],
        evidence: [],
      };
    }

    return {
      decision: 'deny',
      risk_level: 'medium',
      risk_tags: ['PATH_NOT_ALLOWED'],
      evidence: [
        {
          type: 'path_access_denied',
          field: 'path',
          match: file.path,
          description: `Path ${file.path} not in allowlist`,
        },
      ],
      explanation: `${type === 'read_file' ? 'Read' : 'Write'} access to '${file.path}' is not allowed`,
    };
  }

  /**
   * Simulate Web3 transaction/signature
   */
  async simulateWeb3(intent: Web3Intent): Promise<Web3SimulationResult> {
    const evidence: ActionEvidence[] = [];
    const riskTags: string[] = [];
    let riskLevel: RiskLevel = 'low';
    let decision: Decision = 'allow';

    // Check if GoPlus is configured
    if (!GoPlusClient.isConfigured()) {
      return {
        decision: 'confirm',
        risk_level: 'medium',
        risk_tags: ['SIMULATION_UNAVAILABLE'],
        explanation: 'GoPlus API not configured - cannot simulate transaction',
        guardrail: {
          require_user_confirmation: true,
          suggested_change: 'Configure GOPLUS_API_KEY and GOPLUS_API_SECRET',
        },
      };
    }

    // Check origin for phishing
    if (intent.origin) {
      try {
        const phishingResult = await this.goplus.phishingSite(intent.origin);
        if (phishingResult.is_phishing || phishingResult.phishing_site) {
          return {
            decision: 'deny',
            risk_level: 'critical',
            risk_tags: ['PHISHING_ORIGIN'],
            explanation: 'Transaction origin is a known phishing site',
            goplus: {
              address_risk: {
                is_malicious: false,
                is_phishing: true,
              },
            },
          };
        }
      } catch (err) {
        // Continue
      }
    }

    // Check target address
    try {
      const addressResult = await this.goplus.addressSecurity(
        intent.chain_id.toString(),
        [intent.to]
      );
      const addressRisk = addressResult[intent.to.toLowerCase()];

      if (addressRisk) {
        const isMalicious =
          addressRisk.is_blacklisted ||
          addressRisk.is_phishing_activities ||
          addressRisk.is_stealing_attack;

        if (isMalicious) {
          return {
            decision: 'deny',
            risk_level: 'critical',
            risk_tags: ['MALICIOUS_ADDRESS'],
            explanation: 'Target address is flagged as malicious',
            goplus: {
              address_risk: {
                is_malicious: true,
                is_phishing: addressRisk.is_phishing_activities,
                risk_type: Object.entries(addressRisk)
                  .filter(([_, v]) => v === true)
                  .map(([k]) => k),
              },
            },
          };
        }
      }
    } catch (err) {
      evidence.push({
        type: 'address_check_failed',
        description: 'Could not verify target address',
      });
    }

    // Simulate transaction
    try {
      const simulation = await this.goplus.simulateTransaction({
        chain_id: intent.chain_id.toString(),
        from: intent.from,
        to: intent.to,
        value: intent.value,
        data: intent.data,
      });

      // Check for unlimited approvals
      const unlimitedApprovals = simulation.approval_changes.filter(
        (a) => a.is_unlimited
      );

      if (unlimitedApprovals.length > 0) {
        riskTags.push('UNLIMITED_APPROVAL');
        riskLevel = 'high';
        decision = 'confirm';
      }

      // Add all simulation risk tags
      riskTags.push(...simulation.risk_tags);

      // Determine final risk level
      if (simulation.risk_level === 'critical') {
        riskLevel = 'critical';
        decision = 'deny';
      } else if (simulation.risk_level === 'high') {
        riskLevel = 'high';
        if (decision === 'allow') decision = 'confirm';
      }

      return {
        decision,
        risk_level: riskLevel,
        risk_tags: riskTags,
        explanation: !simulation.success
          ? simulation.error_message || 'Simulation failed'
          : unlimitedApprovals.length > 0
          ? 'Unlimited token approval detected'
          : riskTags.length > 0
          ? `Risks detected: ${riskTags.join(', ')}`
          : 'Transaction appears safe',
        goplus: {
          simulation: {
            success: simulation.success,
            balance_changes: simulation.balance_changes.map((c) => ({
              asset_type: c.token_address ? 'erc20' : 'native',
              token_address: c.token_address,
              amount: c.amount,
              direction: c.direction,
            })),
            approval_changes: simulation.approval_changes,
          },
        },
        guardrail:
          decision === 'confirm'
            ? {
                require_user_confirmation: true,
                suggested_change: unlimitedApprovals.length > 0
                  ? 'Use limited approval amount instead'
                  : undefined,
              }
            : undefined,
      };
    } catch (err) {
      return {
        decision: 'confirm',
        risk_level: 'medium',
        risk_tags: ['SIMULATION_FAILED'],
        explanation: err instanceof Error ? err.message : 'Simulation failed',
        guardrail: {
          require_user_confirmation: true,
        },
      };
    }
  }
}

// Export singleton instance
export const actionScanner = new ActionScanner();

// Re-export types and sub-modules
export * from './detectors/index.js';
export * from './goplus/client.js';
