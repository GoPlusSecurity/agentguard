import axios, { type AxiosInstance } from 'axios';

/**
 * GoPlus API base URL
 */
const API_BASE_URL = 'https://api.gopluslabs.io/api/v1';

/**
 * Token security result
 */
export interface TokenSecurityResult {
  is_honeypot: boolean;
  is_open_source: boolean;
  is_proxy: boolean;
  is_mintable: boolean;
  can_take_back_ownership: boolean;
  owner_change_balance: boolean;
  hidden_owner: boolean;
  selfdestruct: boolean;
  external_call: boolean;
  buy_tax: string;
  sell_tax: string;
  holder_count: string;
  total_supply: string;
  lp_holder_count: string;
  is_true_token: boolean;
  is_airdrop_scam: boolean;
  trust_list: boolean;
  other_potential_risks: string;
}

/**
 * Address security result
 */
export interface AddressSecurityResult {
  is_contract: boolean;
  is_open_source: boolean;
  is_proxy: boolean;
  is_blacklisted: boolean;
  is_whitelisted: boolean;
  is_honeypot_related_address: boolean;
  is_phishing_activities: boolean;
  is_stealing_attack: boolean;
  is_fake_token: boolean;
  is_airdrop_scam: boolean;
  is_malicious_mining_activities: boolean;
  is_darkweb_transactions: boolean;
  is_cybercrime: boolean;
  is_money_laundering: boolean;
  is_financial_crime: boolean;
}

/**
 * Approval security result
 */
export interface ApprovalSecurityResult {
  token_address: string;
  token_name: string;
  token_symbol: string;
  is_open_source: boolean;
  is_verified: boolean;
  is_honeypot: boolean;
  spender_address: string;
  spender_tag: string;
  is_contract: boolean;
  doubt_list: boolean;
  approved_amount: string;
}

/**
 * Transaction simulation request
 */
export interface TxSimulationRequest {
  chain_id: string;
  from: string;
  to: string;
  value: string;
  data?: string;
}

/**
 * Balance change from simulation
 */
export interface BalanceChange {
  address: string;
  amount: string;
  token_address?: string;
  token_symbol?: string;
  direction: 'in' | 'out';
}

/**
 * Approval change from simulation
 */
export interface ApprovalChangeResult {
  token_address: string;
  token_symbol?: string;
  spender: string;
  amount: string;
  is_unlimited: boolean;
}

/**
 * Transaction simulation result
 */
export interface TxSimulationResult {
  success: boolean;
  error_message?: string;
  balance_changes: BalanceChange[];
  approval_changes: ApprovalChangeResult[];
  risk_level: 'low' | 'medium' | 'high' | 'critical';
  risk_tags: string[];
}

/**
 * Phishing site result
 */
export interface PhishingSiteResult {
  is_phishing: boolean;
  phishing_site: boolean;
  website_contract_security: boolean;
}

/**
 * GoPlus API client
 */
export class GoPlusClient {
  private client: AxiosInstance;
  private accessToken: string | null = null;
  private tokenExpiresAt: number = 0;

  constructor() {
    this.client = axios.create({
      baseURL: API_BASE_URL,
      timeout: 30000,
    });
  }

  /**
   * Get access token from environment
   */
  private async getAccessToken(): Promise<string> {
    // Check if token is still valid
    if (this.accessToken && Date.now() < this.tokenExpiresAt) {
      return this.accessToken;
    }

    const apiKey = process.env.GOPLUS_API_KEY;
    const apiSecret = process.env.GOPLUS_API_SECRET;

    if (!apiKey || !apiSecret) {
      throw new Error(
        'GoPlus API credentials not found. Set GOPLUS_API_KEY and GOPLUS_API_SECRET environment variables.'
      );
    }

    try {
      const response = await this.client.post('/token', {
        app_key: apiKey,
        app_secret: apiSecret,
      });

      if (response.data.code === 1 && response.data.result?.access_token) {
        this.accessToken = response.data.result.access_token;
        // Token expires in 2 hours, refresh 5 minutes before
        this.tokenExpiresAt = Date.now() + 115 * 60 * 1000;
        return this.accessToken!;
      }

      throw new Error(response.data.message || 'Failed to get access token');
    } catch (error) {
      if (axios.isAxiosError(error)) {
        throw new Error(`GoPlus auth failed: ${error.message}`);
      }
      throw error;
    }
  }

  /**
   * Make authenticated request
   */
  private async request<T>(
    method: 'get' | 'post',
    path: string,
    params?: Record<string, string>,
    data?: unknown
  ): Promise<T> {
    const token = await this.getAccessToken();

    const config = {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      params,
    };

    const response =
      method === 'get'
        ? await this.client.get(path, config)
        : await this.client.post(path, data, config);

    if (response.data.code !== 1) {
      throw new Error(response.data.message || 'GoPlus API error');
    }

    return response.data.result;
  }

  /**
   * Check token security
   */
  async tokenSecurity(
    chainId: string,
    contractAddresses: string[]
  ): Promise<Record<string, TokenSecurityResult>> {
    return this.request(
      'get',
      `/token_security/${chainId}`,
      { contract_addresses: contractAddresses.join(',') }
    );
  }

  /**
   * Check address security (malicious address)
   */
  async addressSecurity(
    chainId: string,
    addresses: string[]
  ): Promise<Record<string, AddressSecurityResult>> {
    return this.request(
      'get',
      `/address_security/${addresses.join(',')}`,
      { chain_id: chainId }
    );
  }

  /**
   * Check approval security
   */
  async approvalSecurity(
    chainId: string,
    contractAddresses: string[]
  ): Promise<ApprovalSecurityResult[]> {
    return this.request(
      'get',
      `/approval_security/${chainId}`,
      { contract_addresses: contractAddresses.join(',') }
    );
  }

  /**
   * Check phishing site
   */
  async phishingSite(url: string): Promise<PhishingSiteResult> {
    const result = await this.request<Record<string, PhishingSiteResult>>(
      'get',
      '/phishing_site',
      { url }
    );
    return result[url] || { is_phishing: false, phishing_site: false, website_contract_security: false };
  }

  /**
   * Simulate transaction
   */
  async simulateTransaction(
    request: TxSimulationRequest
  ): Promise<TxSimulationResult> {
    try {
      const result = await this.request<any>(
        'post',
        '/transaction_security',
        undefined,
        request
      );

      // Parse and normalize the result
      const balanceChanges: BalanceChange[] = [];
      const approvalChanges: ApprovalChangeResult[] = [];
      const riskTags: string[] = [];

      // Extract balance changes
      if (result.balance_change) {
        for (const change of result.balance_change) {
          balanceChanges.push({
            address: change.address || request.from,
            amount: change.amount || '0',
            token_address: change.token_address,
            token_symbol: change.token_symbol,
            direction: parseFloat(change.amount || '0') < 0 ? 'out' : 'in',
          });
        }
      }

      // Extract approval changes
      if (result.approval_change) {
        for (const change of result.approval_change) {
          const isUnlimited =
            change.amount === 'unlimited' ||
            change.amount === 'max' ||
            parseFloat(change.amount || '0') > 1e18;

          approvalChanges.push({
            token_address: change.token_address,
            token_symbol: change.token_symbol,
            spender: change.spender,
            amount: change.amount || '0',
            is_unlimited: isUnlimited,
          });

          if (isUnlimited) {
            riskTags.push('UNLIMITED_APPROVAL');
          }
        }
      }

      // Extract risk tags
      if (result.risk_type && Array.isArray(result.risk_type)) {
        riskTags.push(...result.risk_type);
      }

      // Determine risk level
      let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';

      if (
        riskTags.includes('UNLIMITED_APPROVAL') ||
        riskTags.includes('malicious_address') ||
        riskTags.includes('phishing')
      ) {
        riskLevel = 'high';
      } else if (riskTags.length > 0) {
        riskLevel = 'medium';
      }

      return {
        success: result.simulation_success !== false,
        error_message: result.error_message,
        balance_changes: balanceChanges,
        approval_changes: approvalChanges,
        risk_level: riskLevel,
        risk_tags: riskTags,
      };
    } catch (error) {
      // Return error result
      return {
        success: false,
        error_message:
          error instanceof Error ? error.message : 'Simulation failed',
        balance_changes: [],
        approval_changes: [],
        risk_level: 'high',
        risk_tags: ['SIMULATION_FAILED'],
      };
    }
  }

  /**
   * Check if GoPlus credentials are configured
   */
  static isConfigured(): boolean {
    return !!(process.env.GOPLUS_API_KEY && process.env.GOPLUS_API_SECRET);
  }
}

// Export singleton instance
export const goplusClient = new GoPlusClient();
