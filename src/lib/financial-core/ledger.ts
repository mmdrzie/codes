/**
 * Double-Entry Accounting Ledger System
 * Immutable, append-only ledger with debit/credit enforcement
 */

import { Redis } from '@upstash/redis';
import { logger } from '../logger';
import { SecurityMonitor } from '../security-monitoring';

// Redis for ledger storage
const redis = Redis.fromEnv();
const LEDGER_ENTRY_PREFIX = 'ledger_entry:';
const LEDGER_BALANCE_PREFIX = 'ledger_balance:';
const LEDGER_ACCOUNTS_SET = 'ledger_accounts';
const LEDGER_TRANSACTIONS_SET = 'ledger_transactions';

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
        SecurityMonitor.SecurityEvent.SUSPICIOUS_ACTIVITY,
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
        SecurityMonitor.SecurityEvent.SUSPICIOUS_ACTIVITY,
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
    // This is a simplified implementation
    // In a real system, you'd want to use a more efficient indexing strategy
    // For now, we'll retrieve all entries for the account
    
    // In a production system, we would implement proper indexing and pagination
    const allEntries = await this.getAllLedgerEntriesForAccount(accountId);
    
    // Filter by date if specified
    if (startDate || endDate) {
      return allEntries.filter(entry => {
        if (startDate && entry.timestamp < startDate) return false;
        if (endDate && entry.timestamp > endDate) return false;
        return true;
      });
    }
    
    return allEntries;
  }

  /**
   * Get all ledger entries for an account (simplified implementation)
   */
  private static async getAllLedgerEntriesForAccount(accountId: string): Promise<LedgerEntry[]> {
    // In a real system, this would require proper indexing
    // For now, we'll just return an empty array to indicate the method exists
    // A production implementation would use Redis streams, sorted sets, or external DB
    logger.warn('Retrieving all ledger entries for account - this is a simplified implementation', {
      accountId
    });
    
    return [];
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
   * Verify that all balances are mathematically correct
   */
  static async performLedgerReconciliation(): Promise<{
    success: boolean;
    discrepancies: Array<{ accountId: string; calculatedBalance: number; storedBalance: number }>;
    message: string;
  }> {
    try {
      // Get all accounts
      const accounts = await redis.smembers(LEDGER_ACCOUNTS_SET);
      
      const discrepancies: Array<{ accountId: string; calculatedBalance: number; storedBalance: number }> = [];
      
      for (const accountId of accounts) {
        // Calculate balance from ledger entries (simplified)
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
        
        if (storedBalance && Math.abs(calculatedBalance - storedBalance.currentBalance) > 0.01) {
          discrepancies.push({
            accountId,
            calculatedBalance,
            storedBalance: storedBalance.currentBalance
          });
        }
      }
      
      if (discrepancies.length === 0) {
        logger.info('Ledger reconciliation completed successfully - no discrepancies found');
        return {
          success: true,
          discrepancies: [],
          message: 'Ledger reconciliation completed successfully - no discrepancies found'
        };
      } else {
        logger.error('Ledger reconciliation found discrepancies', { discrepancies });
        return {
          success: false,
          discrepancies,
          message: `Ledger reconciliation found ${discrepancies.length} discrepancies`
        };
      }
    } catch (error) {
      logger.error('Ledger reconciliation failed', { error: (error as Error).message });
      return {
        success: false,
        discrepancies: [],
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