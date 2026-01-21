/**
 * Double-Entry Accounting Ledger System
 * Immutable, append-only ledger with debit/credit enforcement
 */

import { Redis } from '@upstash/redis';
import { logger } from '../logger';
import { SecurityMonitor, SecurityEvent } from '../security-monitoring';

// Redis for ledger storage
const redis = Redis.fromEnv();
const LEDGER_ENTRY_PREFIX = 'ledger_entry:';
const LEDGER_BALANCE_PREFIX = 'ledger_balance:';
const LEDGER_ACCOUNTS_SET = 'ledger_accounts';
const LEDGER_TRANSACTIONS_SET = 'ledger_transactions';
const LEDGER_ENTRIES_BY_ACCOUNT = 'ledger_entries_by_account:'; // Sorted set for indexing entries by account
const LEDGER_GLOBAL_DEBITS = 'ledger_global_debits';
const LEDGER_GLOBAL_CREDITS = 'ledger_global_credits';

// Financial transaction types
export enum TransactionType {
  DEPOSIT = 'deposit',
  WITHDRAWAL = 'withdrawal',
  TRANSFER = 'transfer',
  PAYMENT = 'payment',
  FEE = 'fee',
  REFUND = 'refund',
  ADJUSTMENT = 'adjustment'
}

// Ledger entry interface
export interface LedgerEntry {
  id: string;
  transactionId: string;
  accountId: string;
  amount: number; // Amount in smallest currency unit (e.g., cents)
  type: 'debit' | 'credit';
  description: string;
  timestamp: number; // Unix timestamp
  referenceId?: string; // External reference
  userId?: string; // User who initiated the transaction
  metadata?: Record<string, any>; // Additional transaction metadata
  signature: string; // Cryptographic signature of the transaction
  correlationId: string; // For event correlation
}

// Account balance interface
export interface AccountBalance {
  accountId: string;
  totalDebits: number;
  totalCredits: number;
  currentBalance: number; // credits - debits
  lastUpdated: number;
  version: number;
}

// Transaction interface for atomic operations
export interface FinancialTransaction {
  id: string;
  type: TransactionType;
  amount: number; // Total transaction amount
  entries: Array<{
    accountId: string;
    amount: number; // Amount for this specific entry (positive for credit, negative for debit)
    description: string;
  }>;
  description: string;
  timestamp: number;
  userId?: string;
  referenceId?: string;
  metadata?: Record<string, any>;
  correlationId: string;
}

export class DoubleEntryLedger {
  /**
   * Record a financial transaction with double-entry accounting
   * Ensures that debits equal credits (sum of amounts = 0)
   */
  static async recordTransaction(transaction: FinancialTransaction): Promise<boolean> {
    // Validate that debits equal credits
    const totalAmount = transaction.entries.reduce((sum, entry) => sum + entry.amount, 0);
    
    if (Math.abs(totalAmount) > 0.01) { // Allow small rounding differences
      logger.error('Double-entry accounting violation: debits do not equal credits', {
        transactionId: transaction.id,
        totalAmount,
        entries: transaction.entries
      });
      
      await SecurityMonitor.logEvent(
        SecurityEvent.SUSPICIOUS_ACTIVITY,
        {
          userId: transaction.userId,
          timestamp: new Date(),
          metadata: {
            transactionId: transaction.id,
            violation: 'double_entry_violation',
            totalAmount,
            entries: transaction.entries
          }
        },
        `Double-entry accounting violation in transaction ${transaction.id}`
      );
      
      return false;
    }

    // Generate unique ID for this ledger operation
    const operationId = `op_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    try {
      // Create ledger entries for each transaction entry
      const ledgerEntries: LedgerEntry[] = [];
      
      for (const entry of transaction.entries) {
        // Determine if this is a debit or credit
        const isDebit = entry.amount < 0;
        const amount = Math.abs(entry.amount);
        
        // Create ledger entry
        const ledgerEntry: LedgerEntry = {
          id: `entry_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
          transactionId: transaction.id,
          accountId: entry.accountId,
          amount,
          type: isDebit ? 'debit' : 'credit',
          description: entry.description,
          timestamp: transaction.timestamp,
          referenceId: transaction.referenceId,
          userId: transaction.userId,
          metadata: transaction.metadata,
          signature: this.generateTransactionSignature(transaction, entry),
          correlationId: transaction.correlationId
        };
        
        ledgerEntries.push(ledgerEntry);
      }
      
      // Begin atomic operation using Redis multi
      const multi = redis.multi();
      
      // Add each ledger entry to the ledger
      for (const entry of ledgerEntries) {
        // Store the ledger entry
        const entryKey = `${LEDGER_ENTRY_PREFIX}${entry.id}`;
        multi.set(entryKey, JSON.stringify(entry));
        
        // Add to transaction index
        multi.sadd(LEDGER_TRANSACTIONS_SET, entry.transactionId);
        
        // Update account balance
        await this.updateAccountBalance(multi, entry);
        
        // Add to accounts set
        multi.sadd(LEDGER_ACCOUNTS_SET, entry.accountId);
      }
      
      // Execute all operations atomically
      await multi.exec();
      
      logger.info('Financial transaction recorded successfully', {
        transactionId: transaction.id,
        entriesCount: ledgerEntries.length,
        operationId
      });
      
      return true;
    } catch (error) {
      logger.error('Failed to record financial transaction', {
        error: (error as Error).message,
        transactionId: transaction.id,
        operationId
      });
      
      await SecurityMonitor.logEvent(
        SecurityEvent.SUSPICIOUS_ACTIVITY,
        {
          userId: transaction.userId,
          timestamp: new Date(),
          metadata: {
            transactionId: transaction.id,
            operationId,
            error: (error as Error).message
          }
        },
        `Failed to record financial transaction ${transaction.id}`
      );
      
      return false;
    }
  }

  /**
   * Update account balance atomically
   */
  private static async updateAccountBalance(multi: any, entry: LedgerEntry): Promise<void> {
    const balanceKey = `${LEDGER_BALANCE_PREFIX}${entry.accountId}`;
    
    // Get current balance
    const currentBalanceStr = await redis.get(balanceKey);
    let currentBalance: AccountBalance;
    
    if (currentBalanceStr) {
      currentBalance = JSON.parse(currentBalanceStr as string);
    } else {
      currentBalance = {
        accountId: entry.accountId,
        totalDebits: 0,
        totalCredits: 0,
        currentBalance: 0,
        lastUpdated: Date.now(),
        version: 0
      };
    }
    
    // Update balance based on entry type
    if (entry.type === 'debit') {
      currentBalance.totalDebits += entry.amount;
    } else {
      currentBalance.totalCredits += entry.amount;
    }
    
    currentBalance.currentBalance = currentBalance.totalCredits - currentBalance.totalDebits;
    currentBalance.lastUpdated = Date.now();
    currentBalance.version++;
    
    // Set updated balance
    multi.set(balanceKey, JSON.stringify(currentBalance));
    
    // Add entry to the account's sorted set index (timestamp as score)
    const accountIndexKey = `${LEDGER_ENTRIES_BY_ACCOUNT}${entry.accountId}`;
    multi.zadd(accountIndexKey, { member: entry.id, score: entry.timestamp });
    
    // Update global debits/credits totals
    if (entry.type === 'debit') {
      multi.incrbyfloat(LEDGER_GLOBAL_DEBITS, entry.amount);
    } else {
      multi.incrbyfloat(LEDGER_GLOBAL_CREDITS, entry.amount);
    }
  }

  /**
   * Get account balance
   */
  static async getAccountBalance(accountId: string): Promise<AccountBalance | null> {
    const balanceKey = `${LEDGER_BALANCE_PREFIX}${accountId}`;
    const balanceStr = await redis.get(balanceKey);
    
    if (balanceStr) {
      return JSON.parse(balanceStr as string);
    }
    
    return null;
  }

  /**
   * Get account statement (all ledger entries for an account)
   */
  static async getAccountStatement(
    accountId: string,
    startDate?: number,
    endDate?: number
  ): Promise<LedgerEntry[]> {
    // Retrieve all entries for the account using the indexed method
    return await this.getAllLedgerEntriesForAccount(accountId, startDate, endDate);
  }

  /**
   * Get all ledger entries for an account with proper indexing
   */
  static async getAllLedgerEntriesForAccount(
    accountId: string,
    startDate?: number,
    endDate?: number
  ): Promise<LedgerEntry[]> {
    try {
      // Get all entry IDs for the account from the sorted set
      const accountIndexKey = `${LEDGER_ENTRIES_BY_ACCOUNT}${accountId}`;
      
      let entryIds: string[];
      if (startDate || endDate) {
        // Filter by date range if specified
        const startScore = startDate ? startDate : 0;
        const endScore = endDate ? endDate : '+inf';
        
        const rawEntries = await redis.zrangebyscore(accountIndexKey, startScore, endScore);
        entryIds = rawEntries.map(entry => entry as string);
      } else {
        // Get all entries for the account
        const rawEntries = await redis.zrange(accountIndexKey, 0, -1);
        entryIds = rawEntries.map(entry => entry as string);
      }
      
      // Fetch the actual ledger entries by their IDs
      const entries: LedgerEntry[] = [];
      for (const entryId of entryIds) {
        const entryKey = `${LEDGER_ENTRY_PREFIX}${entryId}`;
        const entryStr = await redis.get(entryKey);
        
        if (entryStr) {
          const entry = JSON.parse(entryStr as string);
          entries.push(entry);
        }
      }
      
      // Sort by timestamp to ensure consistent ordering
      entries.sort((a, b) => a.timestamp - b.timestamp);
      
      return entries;
    } catch (error) {
      logger.error('Error retrieving ledger entries for account', {
        error: (error as Error).message,
        accountId,
        startDate,
        endDate
      });
      
      await SecurityMonitor.logEvent(
        SecurityEvent.SUSPICIOUS_ACTIVITY,
        {
          userId: 'system',
          timestamp: new Date(),
          metadata: {
            accountId,
            startDate,
            endDate,
            error: (error as Error).message
          }
        },
        `Failed to retrieve ledger entries for account ${accountId}`
      );
      
      throw error;
    }
  }

  /**
   * Generate a cryptographic signature for the transaction entry
   */
  private static generateTransactionSignature(transaction: FinancialTransaction, entry: any): string {
    // In a real system, this would use proper cryptographic signing
    // For now, we'll use a simple hash-based approach
    const crypto = require('crypto');
    const data = JSON.stringify({
      transactionId: transaction.id,
      accountId: entry.accountId,
      amount: entry.amount,
      timestamp: transaction.timestamp,
      type: transaction.type
    });
    
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Verify that all balances are mathematically correct and enforce hard invariants
   */
  static async performLedgerReconciliation(): Promise<{
    success: boolean;
    discrepancies: Array<{ accountId: string; calculatedBalance: number; storedBalance: number; issue: string }>;
    globalIssues: Array<{ type: string; details: any }>;
    message: string;
  }> {
    try {
      logger.info('Starting comprehensive ledger reconciliation');
      
      // Initialize results
      const discrepancies: Array<{ accountId: string; calculatedBalance: number; storedBalance: number; issue: string }> = [];
      const globalIssues: Array<{ type: string; details: any }> = [];

      // 1. PER-ACCOUNT RECONCILIATION
      const accounts = await redis.smembers(LEDGER_ACCOUNTS_SET);
      
      for (const accountId of accounts) {
        // Calculate balance from ledger entries
        const accountEntries = await this.getAllLedgerEntriesForAccount(accountId);
        
        // Calculate expected balance from entries
        let calculatedDebits = 0;
        let calculatedCredits = 0;
        
        for (const entry of accountEntries) {
          if (entry.type === 'debit') {
            calculatedDebits += entry.amount;
          } else {
            calculatedCredits += entry.amount;
          }
        }
        
        const calculatedBalance = calculatedCredits - calculatedDebits;
        
        // Get stored balance
        const storedBalance = await this.getAccountBalance(accountId);
        
        if (storedBalance) {
          // Check if calculated vs stored balance matches
          if (Math.abs(calculatedBalance - storedBalance.currentBalance) > 0.01) {
            discrepancies.push({
              accountId,
              calculatedBalance,
              storedBalance: storedBalance.currentBalance,
              issue: 'balance_mismatch'
            });
          }
          
          // Check if stored balance components match calculated components
          if (Math.abs(calculatedDebits - storedBalance.totalDebits) > 0.01) {
            discrepancies.push({
              accountId,
              calculatedBalance,
              storedBalance: storedBalance.currentBalance,
              issue: 'total_debits_mismatch'
            });
          }
          
          if (Math.abs(calculatedCredits - storedBalance.totalCredits) > 0.01) {
            discrepancies.push({
              accountId,
              calculatedBalance,
              storedBalance: storedBalance.currentBalance,
              issue: 'total_credits_mismatch'
            });
          }
          
          // Check negative balance invariant (unless explicitly allowed)
          if (calculatedBalance < 0) {
            // Log this as a potential issue but don't fail immediately - depends on business rules
            logger.warn('Account has negative balance', {
              accountId,
              calculatedBalance,
              details: 'This may be intentional depending on account type (e.g., credit accounts)'
            });
          }
        }
      }

      // 2. GLOBAL SYSTEM INVARIANT CHECKS
      // Check global debits vs credits (should be approximately equal in a closed system)
      const globalDebits = await redis.get(LEDGER_GLOBAL_DEBITS);
      const globalCredits = await redis.get(LEDGER_GLOBAL_CREDITS);
      
      const totalGlobalDebits = globalDebits ? parseFloat(globalDebits as string) : 0;
      const totalGlobalCredits = globalCredits ? parseFloat(globalCredits as string) : 0;
      
      // In a properly balanced double-entry system, global debits should equal global credits
      // However, small discrepancies may occur due to floating point precision
      if (Math.abs(totalGlobalDebits - totalGlobalCredits) > 0.01) {
        globalIssues.push({
          type: 'global_double_entry_violation',
          details: {
            totalGlobalDebits,
            totalGlobalCredits,
            difference: totalGlobalDebits - totalGlobalCredits
          }
        });
      }
      
      // 3. TOTAL SYSTEM BALANCE CONSISTENCY
      let totalSystemBalance = 0;
      for (const accountId of accounts) {
        const balance = await this.getAccountBalance(accountId);
        if (balance) {
          totalSystemBalance += balance.currentBalance;
        }
      }
      
      // The total system balance should be close to zero in a closed system
      // (assets = liabilities + equity, so net should be zero)
      if (Math.abs(totalSystemBalance) > 0.01) {
        globalIssues.push({
          type: 'system_balance_non_zero',
          details: {
            totalSystemBalance,
            accountCount: accounts.length
          }
        });
      }
      
      // 4. IDEMPOTENCY CHECK - verify no duplicate transaction IDs
      // We'll check a sample of ledger entries to detect potential duplicates
      const allLedgerKeys = await redis.keys(`${LEDGER_ENTRY_PREFIX}*`);
      const transactionCounts: Record<string, number> = {};
      
      for (const entryKey of allLedgerKeys) {
        const entryStr = await redis.get(entryKey);
        if (entryStr) {
          const entry = JSON.parse(entryStr as string);
          transactionCounts[entry.transactionId] = (transactionCounts[entry.transactionId] || 0) + 1;
        }
      }
      
      for (const [txId, count] of Object.entries(transactionCounts)) {
        if (count > 1) {
          globalIssues.push({
            type: 'duplicate_transaction',
            details: {
              transactionId: txId,
              occurrenceCount: count
            }
          });
        }
      }

      // 5. LOG RESULTS AND EMIT CRITICAL EVENTS IF NEEDED
      if (discrepancies.length > 0 || globalIssues.length > 0) {
        logger.error('Ledger reconciliation found issues', { 
          discrepancies, 
          globalIssues,
          discrepancyCount: discrepancies.length,
          globalIssueCount: globalIssues.length
        });
        
        // EMIT CRITICAL SIEM EVENT
        await SecurityMonitor.logEvent(
          SecurityEvent.CRITICAL,
          {
            userId: 'system',
            timestamp: new Date(),
            metadata: {
              event: 'ledger_reconciliation_issues',
              discrepancies,
              globalIssues,
              discrepancyCount: discrepancies.length,
              globalIssueCount: globalIssues.length
            }
          },
          'CRITICAL: Ledger reconciliation detected mathematical inconsistencies'
        );
        
        return {
          success: false,
          discrepancies,
          globalIssues,
          message: `Ledger reconciliation failed: ${discrepancies.length} account discrepancies, ${globalIssues.length} global issues`
        };
      } else {
        logger.info('Ledger reconciliation completed successfully - all invariants verified');
        
        // EMIT SUCCESS EVENT
        await SecurityMonitor.logEvent(
          SecurityEvent.INFO,
          {
            userId: 'system',
            timestamp: new Date(),
            metadata: {
              event: 'ledger_reconciliation_success',
              accountCount: accounts.length,
              globalDebits: totalGlobalDebits,
              globalCredits: totalGlobalCredits
            }
          },
          'Ledger reconciliation completed successfully'
        );
        
        return {
          success: true,
          discrepancies: [],
          globalIssues: [],
          message: 'Ledger reconciliation completed successfully - all invariants verified'
        };
      }
    } catch (error) {
      logger.error('Ledger reconciliation failed', { error: (error as Error).message });
      
      // EMIT CRITICAL SIEM EVENT
      await SecurityMonitor.logEvent(
        SecurityEvent.CRITICAL,
        {
          userId: 'system',
          timestamp: new Date(),
          metadata: {
            event: 'ledger_reconciliation_error',
            error: (error as Error).message,
            stack: (error as Error).stack
          }
        },
        `CRITICAL: Ledger reconciliation failed with error: ${(error as Error).message}`
      );
      
      return {
        success: false,
        discrepancies: [],
        globalIssues: [],
        message: `Ledger reconciliation failed: ${(error as Error).message}`
      };
    }
  }

  /**
   * Check if an account has sufficient funds for a withdrawal
   */
  static async hasSufficientFunds(accountId: string, amount: number): Promise<boolean> {
    const balance = await this.getAccountBalance(accountId);
    return balance !== null && balance.currentBalance >= amount;
  }
}