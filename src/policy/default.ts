import type { CapabilityModel } from '../types/skill.js';

/**
 * Default policy configuration
 */
export interface PolicyConfig {
  /** Default action for secret exfiltration */
  secret_exfil: {
    private_key: 'deny' | 'confirm';
    mnemonic: 'deny' | 'confirm';
    api_secret: 'deny' | 'confirm';
  };
  /** Default action for command execution */
  exec_command: 'allow' | 'deny' | 'confirm';
  /** Web3 policies */
  web3: {
    unlimited_approval: 'allow' | 'deny' | 'confirm';
    unknown_spender: 'allow' | 'deny' | 'confirm';
    user_not_present: 'allow' | 'deny' | 'confirm';
  };
  /** Network policies */
  network: {
    untrusted_domain: 'allow' | 'deny' | 'confirm';
    body_contains_secret: 'allow' | 'deny' | 'confirm';
  };
}

/**
 * Default policies - most restrictive
 */
export const DEFAULT_POLICIES: PolicyConfig = {
  // Private key and mnemonic exfiltration is always blocked
  secret_exfil: {
    private_key: 'deny',
    mnemonic: 'deny',
    api_secret: 'confirm',
  },

  // Command execution is denied by default
  exec_command: 'deny',

  // Web3 transactions
  web3: {
    unlimited_approval: 'confirm',
    unknown_spender: 'confirm',
    user_not_present: 'confirm',
  },

  // Network requests
  network: {
    untrusted_domain: 'confirm',
    body_contains_secret: 'deny',
  },
};

/**
 * Restrictive capability model
 */
export const RESTRICTIVE_CAPABILITY: CapabilityModel = {
  network_allowlist: [],
  filesystem_allowlist: [],
  exec: 'deny',
  secrets_allowlist: [],
};

/**
 * Permissive capability model (for trusted skills)
 */
export const PERMISSIVE_CAPABILITY: CapabilityModel = {
  network_allowlist: ['*'],
  filesystem_allowlist: ['./**'],
  exec: 'allow',
  secrets_allowlist: ['*'],
  web3: {
    chains_allowlist: [1, 56, 137, 42161, 10, 8453], // Major chains
    rpc_allowlist: ['*'],
    tx_policy: 'allow',
  },
};

/**
 * Common capability presets
 */
export const CAPABILITY_PRESETS = {
  /** No capabilities */
  none: RESTRICTIVE_CAPABILITY,

  /** Read-only local access */
  read_only: {
    ...RESTRICTIVE_CAPABILITY,
    filesystem_allowlist: ['./**'],
  },

  /** Trading bot preset */
  trading_bot: {
    network_allowlist: [
      'api.binance.com',
      'api.bybit.com',
      'api.okx.com',
      'api.coinbase.com',
      '*.dextools.io',
      '*.coingecko.com',
    ],
    filesystem_allowlist: ['./config/**', './logs/**'],
    exec: 'deny' as const,
    secrets_allowlist: ['*_API_KEY', '*_API_SECRET'],
    web3: {
      chains_allowlist: [1, 56, 137, 42161],
      rpc_allowlist: ['*'],
      tx_policy: 'confirm_high_risk' as const,
    },
  },

  /** DeFi interaction preset */
  defi: {
    network_allowlist: ['*'],
    filesystem_allowlist: [],
    exec: 'deny' as const,
    secrets_allowlist: [],
    web3: {
      chains_allowlist: [1, 56, 137, 42161, 10, 8453, 43114],
      rpc_allowlist: ['*'],
      tx_policy: 'confirm_high_risk' as const,
    },
  },
};
