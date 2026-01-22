import { IncomingMessage } from 'http';
import { 
  getLedger, 
  ImmutableLedger, 
  TransactionIntent 
} from './ledger/immutable-ledger';
import { 
  getSessionManager, 
  DPoPSessionManager 
} from './sessions/dpop-session-manager';
import { 
  getNetworkTrustModel, 
  NetworkTrustModel 
} from './security/network-trust-model';
import { 
  getWalletManager, 
  SecureWalletManager,
  TransactionRequest
} from './wallet/secure-wallet-manager';
import { 
  getKillSwitchController, 
  KillSwitchController,
  isSystemOperational,
  isSystemFrozen
} from './security/kill-switch-controller';
import { 
  getAuditLogger, 
  AuditLogger,
  auditFinancialAction,
  auditSecurityEvent
} from './audit/audit-logger';

export interface FinancialCoreConfig {
  enableKillSwitch: boolean;
  requireDPoPTokens: boolean;
  enforceNetworkTrust: boolean;
  auditAllActions: boolean;
  maxConcurrentTransactions: number;
}

export interface TransactionResult {
  success: boolean;
  transactionId: string;
  error?: string;
  balanceBefore?: { from: number; to: number };
  balanceAfter?: { from: number; to: number };
}

/**
 * Main Financial Core Module
 * Provides secure, auditable financial operations with comprehensive security controls
 */
export class FinancialCore {
  private readonly config: FinancialCoreConfig;
  private readonly ledger: ImmutableLedger;
  private readonly sessionManager: DPoPSessionManager;
  private readonly networkTrustModel: NetworkTrustModel;
  private readonly walletManager: SecureWalletManager;
  private readonly killSwitchController: KillSwitchController;
  private readonly auditLogger: AuditLogger;
  
  // Track concurrent operations to prevent race conditions
  private activeTransactions = new Set<string>();
  private transactionQueue: Array<() => Promise<void>> = [];

  constructor(config?: Partial<FinancialCoreConfig>) {
    this.config = {
      enableKillSwitch: config?.enableKillSwitch ?? true,
      requireDPoPTokens: config?.requireDPoPTokens ?? true,
      enforceNetworkTrust: config?.enforceNetworkTrust ?? true,
      auditAllActions: config?.auditAllActions ?? true,
      maxConcurrentTransactions: config?.maxConcurrentTransactions ?? 10
    };

    this.ledger = getLedger(100); // Snapshot every 100 entries
    this.sessionManager = getSessionManager();
    this.networkTrustModel = getNetworkTrustModel();
    this.walletManager = getWalletManager();
    this.killSwitchController = getKillSwitchController();
    this.auditLogger = getAuditLogger();

    console.log('Financial Core initialized with security controls:', {
      killSwitchEnabled: this.config.enableKillSwitch,
      dpopRequired: this.config.requireDPoPTokens,
      networkTrustEnforced: this.config.enforceNetworkTrust,
      auditingEnabled: this.config.auditAllActions
    });
  }

  /**
   * Process a secure financial transaction with all safety controls
   */
  async processTransaction(
    transactionRequest: TransactionRequest,
    httpRequest?: IncomingMessage
  ): Promise<TransactionResult> {
    const transactionId = this.generateId();

    // Check system state first
    if (isSystemFrozen()) {
      await auditSecurityEvent('transaction_blocked_system_frozen', {
        transactionId,
        userId: transactionRequest.userId,
        fromWallet: transactionRequest.fromWalletId,
        toWallet: transactionRequest.toWalletId,
        amount: transactionRequest.amount
      });
      
      return {
        success: false,
        transactionId,
        error: 'System is currently frozen, no transactions allowed'
      };
    }

    if (!isSystemOperational()) {
      await auditSecurityEvent('transaction_blocked_read_only_mode', {
        transactionId,
        userId: transactionRequest.userId,
        fromWallet: transactionRequest.fromWalletId,
        toWallet: transactionRequest.toWalletId,
        amount: transactionRequest.amount
      });
      
      return {
        success: false,
        transactionId,
        error: 'System is in read-only mode'
      };
    }

    // Validate network trust if enabled
    if (this.config.enforceNetworkTrust && httpRequest) {
      const integrityCheck = this.networkTrustModel.validateRequestIntegrity(httpRequest);
      if (!integrityCheck.valid) {
        await auditSecurityEvent('transaction_network_integrity_violation', {
          transactionId,
          userId: transactionRequest.userId,
          issues: integrityCheck.issues,
          clientIp: httpRequest.socket.remoteAddress
        });

        // Potentially trigger kill switch on severe violations
        if (integrityCheck.issues.some(issue => issue.includes('spoofing'))) {
          await this.killSwitchController.handleSecurityFailure({
            type: 'header_spoofing',
            issues: integrityCheck.issues
          });
        }

        return {
          success: false,
          transactionId,
          error: 'Request integrity violation detected'
        };
      }
    }

    // Audit the transaction attempt
    if (this.config.auditAllActions) {
      await auditFinancialAction('transaction_attempt', {
        transactionId,
        userId: transactionRequest.userId,
        fromWallet: transactionRequest.fromWalletId,
        toWallet: transactionRequest.toWalletId,
        amount: transactionRequest.amount,
        currency: transactionRequest.currency,
        httpRequest: httpRequest ? {
          clientIp: httpRequest.socket.remoteAddress,
          userAgent: httpRequest.headers['user-agent']
        } : undefined
      });
    }

    try {
      // Check for transaction concurrency limits
      if (this.activeTransactions.size >= this.config.maxConcurrentTransactions) {
        // Add to queue instead of rejecting immediately
        return await new Promise((resolve) => {
          this.transactionQueue.push(async () => {
            const result = await this.executeTransaction(transactionRequest, transactionId);
            resolve(result);
          });
        });
      }

      return await this.executeTransaction(transactionRequest, transactionId);
    } catch (error) {
      await auditSecurityEvent('transaction_error', {
        transactionId,
        userId: transactionRequest.userId,
        error: error instanceof Error ? error.message : String(error),
        stack: error instanceof Error ? error.stack : undefined
      });

      return {
        success: false,
        transactionId,
        error: 'Transaction processing error'
      };
    }
  }

  private async executeTransaction(
    transactionRequest: TransactionRequest,
    transactionId: string
  ): Promise<TransactionResult> {
    // Add to active transactions to prevent race conditions
    this.activeTransactions.add(transactionId);

    try {
      // Get balances before transaction
      const fromBalanceBefore = await this.walletManager.getBalance(transactionRequest.fromWalletId);
      const toBalanceBefore = await this.walletManager.getBalance(transactionRequest.toWalletId);

      if (fromBalanceBefore === null || toBalanceBefore === null) {
        return {
          success: false,
          transactionId,
          error: 'Unable to retrieve wallet balances',
          balanceBefore: { from: fromBalanceBefore ?? 0, to: toBalanceBefore ?? 0 }
        };
      }

      // Process the transaction through the secure wallet manager
      const result = await this.walletManager.processTransaction(transactionRequest);

      if (!result.success) {
        await auditFinancialAction('transaction_failed', {
          transactionId,
          userId: transactionRequest.userId,
          fromWallet: transactionRequest.fromWalletId,
          toWallet: transactionRequest.toWalletId,
          amount: transactionRequest.amount,
          currency: transactionRequest.currency,
          error: result.error
        });

        return {
          success: false,
          transactionId,
          error: result.error,
          balanceBefore: { from: fromBalanceBefore, to: toBalanceBefore }
        };
      }

      // Get balances after transaction
      const fromBalanceAfter = await this.walletManager.getBalance(transactionRequest.fromWalletId);
      const toBalanceAfter = await this.walletManager.getBalance(transactionRequest.toWalletId);

      // Audit successful transaction
      if (this.config.auditAllActions) {
        await auditFinancialAction('transaction_success', {
          transactionId: result.transactionId,
          userId: transactionRequest.userId,
          fromWallet: transactionRequest.fromWalletId,
          toWallet: transactionRequest.toWalletId,
          amount: transactionRequest.amount,
          currency: transactionRequest.currency,
          balanceBefore: { from: fromBalanceBefore, to: toBalanceBefore },
          balanceAfter: { from: fromBalanceAfter, to: toBalanceAfter }
        });
      }

      return {
        success: true,
        transactionId: result.transactionId,
        balanceBefore: { from: fromBalanceBefore, to: toBalanceBefore },
        balanceAfter: { from: fromBalanceAfter, to: toBalanceAfter }
      };
    } finally {
      // Remove from active transactions
      this.activeTransactions.delete(transactionId);

      // Process queued transactions if any
      if (this.transactionQueue.length > 0 && 
          this.activeTransactions.size < this.config.maxConcurrentTransactions) {
        const nextTransaction = this.transactionQueue.shift();
        if (nextTransaction) {
          // Process the next transaction asynchronously
          nextTransaction().catch(console.error);
        }
      }
    }
  }

  /**
   * Validate a DPoP token for an HTTP request
   */
  async validateDPoPToken(
    accessToken: string,
    dpopProof: string,
    httpRequest: IncomingMessage
  ): Promise<{ valid: boolean; error?: string; payload?: any }> {
    if (!this.config.requireDPoPTokens) {
      return { valid: true };
    }

    if (!dpopProof || !accessToken) {
      return { valid: false, error: 'DPoP proof and access token required' };
    }

    // Extract method and URL from request
    const method = httpRequest.method || 'GET';
    const url = httpRequest.url || '/';
    const fullUrl = `https://${httpRequest.headers.host}${url}`;

    return await this.sessionManager.validateDPoPProof(dpopProof, method, fullUrl, accessToken);
  }

  /**
   * Get client IP address respecting network trust model
   */
  getClientIpAddress(httpRequest: IncomingMessage): string {
    return this.networkTrustModel.getClientIpAddress(httpRequest);
  }

  /**
   * Activate the kill switch to halt all operations
   */
  async activateKillSwitch(activatedBy: string, reason: string): Promise<boolean> {
    if (!this.config.enableKillSwitch) {
      return false;
    }
    
    return await this.killSwitchController.activateEmergencyFreeze(activatedBy, reason);
  }

  /**
   * Deactivate the kill switch to resume operations
   */
  async deactivateKillSwitch(activatedBy: string, reason: string): Promise<boolean> {
    if (!this.config.enableKillSwitch) {
      return false;
    }
    
    return await this.killSwitchController.deactivate(activatedBy, reason);
  }

  /**
   * Create a new wallet
   */
  async createWallet(userId: string, currency: string): Promise<any> {
    if (isSystemFrozen()) {
      throw new Error('System is frozen, cannot create wallets');
    }

    const wallet = await this.walletManager.createWallet({ userId, currency });

    if (this.config.auditAllActions) {
      await auditFinancialAction('wallet_created', {
        walletId: wallet.id,
        userId,
        currency
      });
    }

    return wallet;
  }

  /**
   * Get wallet information
   */
  async getWallet(walletId: string): Promise<any> {
    const wallet = await this.walletManager.getWallet(walletId);
    
    if (wallet && this.config.auditAllActions) {
      await auditFinancialAction('wallet_accessed', {
        walletId,
        userId: wallet.userId
      });
    }

    return wallet;
  }

  /**
   * Freeze a wallet
   */
  async freezeWallet(walletId: string, reason: string = 'admin_action'): Promise<boolean> {
    const result = await this.walletManager.freezeWallet(walletId, reason);

    if (result && this.config.auditAllActions) {
      await auditSecurityEvent('wallet_frozen', {
        walletId,
        reason
      });
    }

    return result;
  }

  /**
   * Verify the integrity of the financial system
   */
  async verifyIntegrity(): Promise<{ 
    ledger: boolean; 
    auditLogs: boolean; 
    overall: boolean; 
    issues: string[] 
  }> {
    const issues: string[] = [];
    
    // Verify ledger integrity
    const ledgerValid = this.ledger.verifyIntegrity();
    if (!ledgerValid) {
      issues.push('Ledger integrity violation');
    }

    // Verify audit log integrity
    const auditLogsValid = await this.auditLogger.verifyAuditLogIntegrity();
    if (!auditLogsValid) {
      issues.push('Audit log integrity violation');
    }

    const overall = ledgerValid && auditLogsValid;

    if (!overall) {
      await auditSecurityEvent('integrity_verification_failed', {
        ledgerValid,
        auditLogsValid,
        issues
      });

      // Potentially trigger kill switch on integrity failures
      if (this.config.enableKillSwitch) {
        await this.killSwitchController.handleSecurityFailure({
          type: 'integrity_violation',
          issues
        });
      }
    }

    return {
      ledger: ledgerValid,
      auditLogs: auditLogsValid,
      overall,
      issues
    };
  }

  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Global singleton instance
let financialCore: FinancialCore | null = null;

export function getFinancialCore(config?: Partial<FinancialCoreConfig>): FinancialCore {
  if (!financialCore) {
    financialCore = new FinancialCore(config);
  }
  return financialCore;
}

// Export individual managers for direct access if needed
export {
  getLedger,
  getSessionManager,
  getNetworkTrustModel,
  getWalletManager,
  getKillSwitchController,
  getAuditLogger
};