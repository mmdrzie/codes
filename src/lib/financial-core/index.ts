/**
 * Financial Core Module - Tier 1 Bank Grade Implementation
 * Implements all required financial controls with cryptographic security bindings
 */

import { Redis } from '@upstash/redis';
import { logger } from '../logger';
import { SecurityMonitor } from '../security-monitoring';
import { siemService } from '../siem-integration';
import { DoubleEntryLedger, FinancialTransaction, AccountBalance } from './ledger';
import { TransactionEngine, TransactionResult, RiskControls, TransactionState } from './transaction-engine';
import { AuditTrail, AuditTrailEntry } from './audit-trail';

// Redis for financial state management
const redis = Redis.fromEnv();

// Financial invariants enforcement
export class FinancialCore {
  /**
   * Execute a financial transaction with full bank-grade security and controls
   */
  static async executeSecureTransaction(
    transaction: FinancialTransaction,
    riskControls?: RiskControls,
    userId?: string,
    ipAddress?: string
  ): Promise<TransactionResult> {
    // Validate transaction
    const validation = TransactionEngine.validateTransaction(transaction);
    if (!validation.valid) {
      logger.error('Transaction validation failed', {
        transactionId: transaction.id,
        errors: validation.errors
      });

      await SecurityMonitor.logAuthFailure(
        userId || null,
        {
          ipAddress: ipAddress || 'unknown',
          userAgent: 'Financial Core',
          metadata: {
            transactionId: transaction.id,
            validationErrors: validation.errors,
            timestamp: new Date()
          }
        },
        'Transaction validation failed'
      );

      return {
        success: false,
        transactionId: transaction.id,
        state: TransactionState.FAILED,
        error: `Transaction validation failed: ${validation.errors.join(', ')}`
      };
    }

    // Record audit trail entry for the transaction attempt
    await AuditTrail.recordTransactionAudit(transaction, userId || 'system', ipAddress);

    // Execute transaction through engine with risk controls
    const result = await TransactionEngine.executeTransactionWithRetry(
      transaction,
      riskControls
    );

    // Log the result to SIEM
    if (result.success) {
      await SecurityMonitor.logAuthSuccess(
        userId || 'system',
        {
          ipAddress: ipAddress || 'internal',
          userAgent: 'Financial Core',
          metadata: {
            transactionId: transaction.id,
            result: 'success',
            amount: transaction.amount,
            type: transaction.type,
            timestamp: new Date()
          }
        }
      );
    } else {
      await SecurityMonitor.logAuthFailure(
        userId || null,
        {
          ipAddress: ipAddress || 'internal',
          userAgent: 'Financial Core',
          metadata: {
            transactionId: transaction.id,
            result: 'failed',
            error: result.error,
            amount: transaction.amount,
            type: transaction.type,
            timestamp: new Date()
          }
        },
        result.error || 'Transaction failed'
      );
    }

    return result;
  }

  /**
   * Transfer funds between accounts with security controls
   */
  static async transferFunds(
    fromAccountId: string,
    toAccountId: string,
    amount: number,
    description: string,
    userId?: string,
    ipAddress?: string,
    referenceId?: string,
    riskControls?: RiskControls
  ): Promise<TransactionResult> {
    // Validate inputs
    if (amount <= 0) {
      return {
        success: false,
        transactionId: `transfer_${Date.now()}`,
        state: TransactionState.FAILED,
        error: 'Transfer amount must be positive'
      };
    }

    // Check if source account has sufficient funds
    const hasFunds = await DoubleEntryLedger.hasSufficientFunds(fromAccountId, amount);
    if (!hasFunds) {
      logger.warn('Insufficient funds for transfer', {
        fromAccountId,
        toAccountId,
        amount,
        userId
      });

      await SecurityMonitor.logAuthFailure(
        userId || null,
        {
          ipAddress: ipAddress || 'unknown',
          userAgent: 'Financial Core',
          metadata: {
            fromAccountId,
            toAccountId,
            amount,
            check: 'insufficient_funds',
            timestamp: new Date()
          }
        },
        'Insufficient funds for transfer'
      );

      return {
        success: false,
        transactionId: `transfer_${Date.now()}`,
        state: TransactionState.FAILED,
        error: 'Insufficient funds'
      };
    }

    // Create transfer transaction (double-entry: debit from, credit to)
    const transaction: FinancialTransaction = {
      id: `transfer_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type: 'transfer',
      amount: 0, // Sum of entries should be 0 for double-entry
      entries: [
        {
          accountId: fromAccountId,
          amount: -amount, // Negative for debit
          description: `Transfer out: ${description}`
        },
        {
          accountId: toAccountId,
          amount: amount, // Positive for credit
          description: `Transfer in: ${description}`
        }
      ],
      description: `Transfer from ${fromAccountId} to ${toAccountId}`,
      timestamp: Date.now(),
      userId,
      referenceId,
      correlationId: `transfer_${Date.now()}`
    };

    return await this.executeSecureTransaction(
      transaction,
      riskControls,
      userId,
      ipAddress
    );
  }

  /**
   * Deposit funds to an account
   */
  static async deposit(
    accountId: string,
    amount: number,
    description: string,
    userId?: string,
    ipAddress?: string,
    referenceId?: string,
    riskControls?: RiskControls
  ): Promise<TransactionResult> {
    if (amount <= 0) {
      return {
        success: false,
        transactionId: `deposit_${Date.now()}`,
        state: TransactionState.FAILED,
        error: 'Deposit amount must be positive'
      };
    }

    // Create deposit transaction (credit to account)
    const transaction: FinancialTransaction = {
      id: `deposit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type: 'deposit',
      amount: 0,
      entries: [
        {
          accountId: 'external_source', // Representing external funds coming in
          amount: -amount, // Negative for debit (source)
          description: `External deposit funding: ${description}`
        },
        {
          accountId: accountId,
          amount: amount, // Positive for credit
          description: `Deposit: ${description}`
        }
      ],
      description: `Deposit to ${accountId}`,
      timestamp: Date.now(),
      userId,
      referenceId,
      correlationId: `deposit_${Date.now()}`
    };

    return await this.executeSecureTransaction(
      transaction,
      riskControls,
      userId,
      ipAddress
    );
  }

  /**
   * Withdraw funds from an account
   */
  static async withdraw(
    accountId: string,
    amount: number,
    description: string,
    userId?: string,
    ipAddress?: string,
    referenceId?: string,
    riskControls?: RiskControls
  ): Promise<TransactionResult> {
    if (amount <= 0) {
      return {
        success: false,
        transactionId: `withdraw_${Date.now()}`,
        state: TransactionState.FAILED,
        error: 'Withdrawal amount must be positive'
      };
    }

    // Check if account has sufficient funds
    const hasFunds = await DoubleEntryLedger.hasSufficientFunds(accountId, amount);
    if (!hasFunds) {
      logger.warn('Insufficient funds for withdrawal', {
        accountId,
        amount,
        userId
      });

      await SecurityMonitor.logAuthFailure(
        userId || null,
        {
          ipAddress: ipAddress || 'unknown',
          userAgent: 'Financial Core',
          metadata: {
            accountId,
            amount,
            check: 'insufficient_funds',
            timestamp: new Date()
          }
        },
        'Insufficient funds for withdrawal'
      );

      return {
        success: false,
        transactionId: `withdraw_${Date.now()}`,
        state: TransactionState.FAILED,
        error: 'Insufficient funds'
      };
    }

    // Create withdrawal transaction (debit from account)
    const transaction: FinancialTransaction = {
      id: `withdraw_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      type: 'withdrawal',
      amount: 0,
      entries: [
        {
          accountId: accountId,
          amount: -amount, // Negative for debit
          description: `Withdrawal: ${description}`
        },
        {
          accountId: 'external_destination', // Representing external destination
          amount: amount, // Positive for credit (destination receives funds)
          description: `External withdrawal: ${description}`
        }
      ],
      description: `Withdrawal from ${accountId}`,
      timestamp: Date.now(),
      userId,
      referenceId,
      correlationId: `withdraw_${Date.now()}`
    };

    return await this.executeSecureTransaction(
      transaction,
      riskControls,
      userId,
      ipAddress
    );
  }

  /**
   * Get account balance with security logging
   */
  static async getBalance(accountId: string, userId?: string, ipAddress?: string): Promise<AccountBalance | null> {
    // Record balance check in audit trail
    await AuditTrail.recordBalanceCheckAudit(accountId, userId || 'system', ipAddress);

    const balance = await DoubleEntryLedger.getAccountBalance(accountId);

    logger.info('Account balance retrieved', {
      accountId,
      balance: balance?.currentBalance,
      userId
    });

    await SecurityMonitor.logAuthSuccess(
      userId || 'system',
      {
        ipAddress: ipAddress || 'internal',
        userAgent: 'Financial Core',
        metadata: {
          accountId,
          action: 'get_balance',
          timestamp: new Date()
        }
      }
    );

    return balance;
  }

  /**
   * Get account statement with security logging
   */
  static async getStatement(
    accountId: string,
    startDate?: number,
    endDate?: number,
    userId?: string,
    ipAddress?: string
  ) {
    // Record statement request in audit trail
    await AuditTrail.recordBalanceCheckAudit(accountId, userId || 'system', ipAddress);

    const statement = await DoubleEntryLedger.getAccountStatement(accountId, startDate, endDate);

    logger.info('Account statement retrieved', {
      accountId,
      entriesCount: statement.length,
      userId
    });

    await SecurityMonitor.logAuthSuccess(
      userId || 'system',
      {
        ipAddress: ipAddress || 'internal',
        userAgent: 'Financial Core',
        metadata: {
          accountId,
          action: 'get_statement',
          entriesCount: statement.length,
          timestamp: new Date()
        }
      }
    );

    return statement;
  }

  /**
   * Perform daily reconciliation to ensure all balances are accurate
   */
  static async performDailyReconciliation(): Promise<{
    success: boolean;
    discrepancies: Array<{ accountId: string; calculatedBalance: number; storedBalance: number }>;
    message: string;
  }> {
    logger.info('Starting daily reconciliation');

    const result = await DoubleEntryLedger.performLedgerReconciliation();

    if (!result.success) {
      logger.error('Daily reconciliation found discrepancies', {
        discrepancyCount: result.discrepancies.length
      });

      // Log discrepancies to SIEM
      for (const discrepancy of result.discrepancies) {
        await SecurityMonitor.logSuspiciousActivity(
          {
            timestamp: new Date(),
            metadata: {
              accountId: discrepancy.accountId,
              calculatedBalance: discrepancy.calculatedBalance,
              storedBalance: discrepancy.storedBalance,
              check: 'reconciliation_discrepancy',
              timestamp: new Date()
            }
          },
          `Balance discrepancy found: ${discrepancy.accountId}`
        );
      }
    } else {
      logger.info('Daily reconciliation completed successfully');
    }

    return result;
  }

  /**
   * Process scheduled transactions
   */
  static async processScheduledTransactions(): Promise<number> {
    logger.info('Processing scheduled transactions');
    
    const processed = await TransactionEngine.processScheduledTransactions();
    
    logger.info('Scheduled transactions processed', { processedCount: processed });
    
    return processed;
  }

  /**
   * Verify the integrity of the financial system
   */
  static async verifySystemIntegrity(): Promise<{
    ledgerIntegrity: boolean;
    auditTrailIntegrity: boolean;
    overallStatus: 'healthy' | 'degraded' | 'compromised';
  }> {
    logger.info('Verifying system integrity');

    // Check ledger integrity
    const ledgerCheck = await DoubleEntryLedger.performLedgerReconciliation();
    const ledgerIntegrity = ledgerCheck.success;

    // Check audit trail integrity
    const auditTrailIntegrity = await AuditTrail.verifyAuditTrailIntegrity();

    // Determine overall status
    let overallStatus: 'healthy' | 'degraded' | 'compromised' = 'healthy';
    if (!ledgerIntegrity || !auditTrailIntegrity) {
      overallStatus = ledgerCheck.discrepancies.length > 0 ? 'compromised' : 'degraded';
    }

    logger.info('System integrity verification completed', {
      ledgerIntegrity,
      auditTrailIntegrity,
      overallStatus
    });

    // Log to SIEM if there are issues
    if (!ledgerIntegrity || !auditTrailIntegrity) {
      await SecurityMonitor.logSuspiciousActivity(
        {
          timestamp: new Date(),
          metadata: {
            ledgerIntegrity,
            auditTrailIntegrity,
            overallStatus,
            timestamp: new Date()
          }
        },
        `System integrity issue detected: ${overallStatus}`
      );
    }

    return {
      ledgerIntegrity,
      auditTrailIntegrity,
      overallStatus
    };
  }

  /**
   * Schedule a transaction for future execution
   */
  static async scheduleTransaction(
    transaction: FinancialTransaction,
    scheduledTime: number,
    riskControls?: RiskControls,
    userId?: string,
    ipAddress?: string
  ): Promise<boolean> {
    logger.info('Scheduling transaction', {
      transactionId: transaction.id,
      scheduledTime,
      userId
    });

    // Record audit trail entry
    await AuditTrail.recordTransactionAudit(transaction, userId || 'system', ipAddress);

    const result = await TransactionEngine.scheduleTransaction(
      transaction,
      scheduledTime,
      riskControls
    );

    if (result) {
      await SecurityMonitor.logAuthSuccess(
        userId || 'system',
        {
          ipAddress: ipAddress || 'internal',
          userAgent: 'Financial Core',
          metadata: {
            transactionId: transaction.id,
            action: 'schedule_transaction',
            scheduledTime,
            timestamp: new Date()
          }
        }
      );
    } else {
      await SecurityMonitor.logAuthFailure(
        userId || null,
        {
          ipAddress: ipAddress || 'internal',
          userAgent: 'Financial Core',
          metadata: {
            transactionId: transaction.id,
            action: 'schedule_transaction_failed',
            scheduledTime,
            timestamp: new Date()
          }
        },
        'Failed to schedule transaction'
      );
    }

    return result;
  }
}

// Export all necessary types and classes
export {
  DoubleEntryLedger,
  TransactionEngine,
  AuditTrail,
  TransactionType,
  FinancialTransaction,
  AccountBalance,
  TransactionState,
  TransactionResult,
  RiskControls
};