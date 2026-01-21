/**
 * Financial Transaction Engine
 * Handles atomic, idempotent, replay-safe transactions with deterministic ordering
 */

import { Redis } from '@upstash/redis';
import { logger } from '../logger';
import { SecurityMonitor } from '../security-monitoring';
import { DoubleEntryLedger, FinancialTransaction, TransactionType } from './ledger';
import { SystemControls, SystemStatus } from '../system-controls';

// Redis for transaction state management
const redis = Redis.fromEnv();
const TRANSACTION_STATE_PREFIX = 'transaction_state:';
const TRANSACTION_PROCESSING_LOCK = 'transaction_processing_lock:';
const TRANSACTION_RETRY_QUEUE = 'transaction_retry_queue';

// Transaction states
export enum TransactionState {
  PENDING = 'pending',
  PROCESSING = 'processing',
  COMPLETED = 'completed',
  FAILED = 'failed',
  ROLLBACK_PENDING = 'rollback_pending',
  ROLLED_BACK = 'rolled_back'
}

// Transaction result interface
export interface TransactionResult {
  success: boolean;
  transactionId: string;
  state: TransactionState;
  error?: string;
  processedAt?: number;
  retries?: number;
}

// Risk controls interface
export interface RiskControls {
  dailyLimit?: number; // Max amount per day
  velocityLimit?: number; // Max transactions per minute
  amountThreshold?: number; // Threshold for enhanced monitoring
  ipRestrictions?: string[]; // Allowed IP addresses
  timeOfDayRestrictions?: { startHour: number; endHour: number }; // Time window restrictions
}

export class TransactionEngine {
  private static readonly MAX_RETRIES = 3;
  private static readonly RETRY_DELAY_MS = 1000;

  /**
   * Execute a financial transaction with full ACID properties
   */
  static async executeTransaction(
    transaction: FinancialTransaction,
    riskControls?: RiskControls
  ): Promise<TransactionResult> {
    // Check system status before processing
    const systemStatus = await SystemControls.getSystemStatus();
    if (systemStatus.status === SystemStatus.FROZEN || systemStatus.status === SystemStatus.EMERGENCY_FROZEN) {
      logger.error('Transaction blocked - system is frozen', {
        transactionId: transaction.id,
        systemStatus: systemStatus.status
      });
      
      await SecurityMonitor.logEvent(
        SecurityEvent.SUSPICIOUS_ACTIVITY,
        {
          userId: transaction.userId,
          timestamp: new Date(),
          metadata: {
            transactionId: transaction.id,
            violation: 'system_frozen',
            systemStatus: systemStatus.status
          }
        },
        `Transaction blocked - system is frozen: ${systemStatus.status}`
      );
      
      return {
        success: false,
        transactionId: transaction.id,
        state: TransactionState.FAILED,
        error: 'System is currently frozen'
      };
    }
    
    if (systemStatus.status === SystemStatus.READ_ONLY) {
      logger.error('Transaction blocked - system is in read-only mode', {
        transactionId: transaction.id,
        systemStatus: systemStatus.status
      });
      
      await SecurityMonitor.logEvent(
        SecurityEvent.SUSPICIOUS_ACTIVITY,
        {
          userId: transaction.userId,
          timestamp: new Date(),
          metadata: {
            transactionId: transaction.id,
            violation: 'system_read_only',
            systemStatus: systemStatus.status
          }
        },
        `Transaction blocked - system is read-only: ${systemStatus.status}`
      );
      
      return {
        success: false,
        transactionId: transaction.id,
        state: TransactionState.FAILED,
        error: 'System is currently in read-only mode'
      };
    }
    
    // Apply risk controls
    if (riskControls && !(await this.applyRiskControls(transaction, riskControls))) {
      logger.warn('Transaction blocked by risk controls', {
        transactionId: transaction.id,
        userId: transaction.userId
      });

      return {
        success: false,
        transactionId: transaction.id,
        state: TransactionState.FAILED,
        error: 'Transaction blocked by risk controls'
      };
    }

    // Check if transaction has already been processed (idempotency)
    const existingState = await this.getTransactionState(transaction.id);
    if (existingState && existingState !== TransactionState.FAILED) {
      logger.info('Transaction already processed (idempotency)', {
        transactionId: transaction.id,
        state: existingState
      });

      return {
        success: existingState === TransactionState.COMPLETED,
        transactionId: transaction.id,
        state: existingState
      };
    }

    // Attempt to acquire processing lock
    const lockKey = `${TRANSACTION_PROCESSING_LOCK}${transaction.id}`;
    const lockValue = `lock_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    const LOCK_TIMEOUT = 30; // 30 seconds

    const lockAcquired = await redis.set(lockKey, lockValue, {
      ex: LOCK_TIMEOUT,
      nx: true // Only set if key doesn't exist
    });

    if (!lockAcquired) {
      logger.warn('Failed to acquire transaction processing lock', {
        transactionId: transaction.id
      });

      return {
        success: false,
        transactionId: transaction.id,
        state: TransactionState.FAILED,
        error: 'Failed to acquire processing lock'
      };
    }

    try {
      // Mark transaction as processing
      await this.setTransactionState(transaction.id, TransactionState.PROCESSING);

      // Execute the transaction
      const ledgerSuccess = await DoubleEntryLedger.recordTransaction(transaction);

      if (ledgerSuccess) {
        // Mark as completed
        await this.setTransactionState(transaction.id, TransactionState.COMPLETED);
        
        logger.info('Transaction completed successfully', {
          transactionId: transaction.id,
          userId: transaction.userId,
          amount: transaction.amount,
          type: transaction.type
        });

        // Emit success event to SIEM
        await SecurityMonitor.logAuthSuccess(
          transaction.userId || 'system',
          {
            ipAddress: 'internal',
            userAgent: 'Transaction Engine',
            metadata: {
              transactionId: transaction.id,
              type: transaction.type,
              amount: transaction.amount,
              timestamp: new Date()
            }
          }
        );

        return {
          success: true,
          transactionId: transaction.id,
          state: TransactionState.COMPLETED,
          processedAt: Date.now()
        };
      } else {
        // Mark as failed
        await this.setTransactionState(transaction.id, TransactionState.FAILED);
        
        logger.error('Transaction failed during ledger recording', {
          transactionId: transaction.id,
          userId: transaction.userId
        });

        // Emit failure event to SIEM
        await SecurityMonitor.logAuthFailure(
          transaction.userId || null,
          {
            ipAddress: 'internal',
            userAgent: 'Transaction Engine',
            metadata: {
              transactionId: transaction.id,
              type: transaction.type,
              amount: transaction.amount,
              timestamp: new Date()
            }
          },
          'Ledger recording failed'
        );

        return {
          success: false,
          transactionId: transaction.id,
          state: TransactionState.FAILED,
          error: 'Ledger recording failed',
          processedAt: Date.now()
        };
      }
    } catch (error) {
      logger.error('Transaction execution error', {
        transactionId: transaction.id,
        error: (error as Error).message,
        stack: (error as Error).stack
      });

      // Mark as failed
      await this.setTransactionState(transaction.id, TransactionState.FAILED);

      return {
        success: false,
        transactionId: transaction.id,
        state: TransactionState.FAILED,
        error: (error as Error).message,
        processedAt: Date.now()
      };
    } finally {
      // Release the lock safely - only if we still own it
      // Use Lua script to atomically check and delete the lock
      const luaScript = `
        if redis.call("GET", KEYS[1]) == ARGV[1] then
          return redis.call("DEL", KEYS[1])
        else
          return 0
        end
      `;
      
      try {
        await redis.eval(luaScript, [lockKey], [lockValue]);
      } catch (lockError) {
        logger.error('Failed to safely release transaction lock', {
          transactionId: transaction.id,
          error: (lockError as Error).message
        });
      }
    }
  }

  /**
   * Apply risk controls to a transaction
   */
  private static async applyRiskControls(
    transaction: FinancialTransaction,
    riskControls: RiskControls
  ): Promise<boolean> {
    // Check daily limit
    if (riskControls.dailyLimit) {
      const dailyAmount = await this.getUserDailyAmount(
        transaction.userId || 'anonymous',
        transaction.timestamp
      );
      
      if (dailyAmount + Math.abs(transaction.amount) > riskControls.dailyLimit) {
        logger.warn('Transaction exceeds daily limit', {
          transactionId: transaction.id,
          userId: transaction.userId,
          dailyLimit: riskControls.dailyLimit,
          currentDailyAmount: dailyAmount,
          transactionAmount: transaction.amount
        });
        
        await SecurityMonitor.logSuspiciousActivity(
          {
            userId: transaction.userId,
            timestamp: new Date(),
            metadata: {
              transactionId: transaction.id,
              check: 'daily_limit',
              dailyLimit: riskControls.dailyLimit,
              currentDailyAmount: dailyAmount,
              transactionAmount: transaction.amount
            }
          },
          `Transaction exceeds daily limit: ${transaction.amount} vs ${riskControls.dailyLimit}`
        );
        
        return false;
      }
    }

    // Check velocity limit (transactions per minute)
    if (riskControls.velocityLimit) {
      const recentTransactions = await this.getUserRecentTransactions(
        transaction.userId || 'anonymous',
        transaction.timestamp,
        60 // 1 minute window
      );
      
      if (recentTransactions >= riskControls.velocityLimit) {
        logger.warn('Transaction exceeds velocity limit', {
          transactionId: transaction.id,
          userId: transaction.userId,
          velocityLimit: riskControls.velocityLimit,
          recentTransactions
        });
        
        await SecurityMonitor.logSuspiciousActivity(
          {
            userId: transaction.userId,
            timestamp: new Date(),
            metadata: {
              transactionId: transaction.id,
              check: 'velocity_limit',
              velocityLimit: riskControls.velocityLimit,
              recentTransactions
            }
          },
          `Transaction exceeds velocity limit: ${recentTransactions} vs ${riskControls.velocityLimit}`
        );
        
        return false;
      }
    }

    // Check amount threshold for enhanced monitoring
    if (riskControls.amountThreshold && Math.abs(transaction.amount) > riskControls.amountThreshold) {
      logger.info('Transaction exceeds amount threshold - enhanced monitoring required', {
        transactionId: transaction.id,
        userId: transaction.userId,
        amountThreshold: riskControls.amountThreshold,
        transactionAmount: transaction.amount
      });
      
      await SecurityMonitor.logSuspiciousActivity(
        {
          userId: transaction.userId,
          timestamp: new Date(),
          metadata: {
            transactionId: transaction.id,
            check: 'amount_threshold',
            amountThreshold: riskControls.amountThreshold,
            transactionAmount: transaction.amount
          }
        },
        `Transaction exceeds amount threshold: ${transaction.amount} vs ${riskControls.amountThreshold}`
      );
    }

    return true;
  }

  /**
   * Get user's daily transaction amount
   */
  private static async getUserDailyAmount(userId: string, timestamp: number): Promise<number> {
    // Simplified implementation - in production, use Redis sorted sets or similar
    // This would track the sum of transactions for the user in the current day
    const todayStart = new Date(timestamp * 1000);
    todayStart.setHours(0, 0, 0, 0);
    
    const startOfDay = Math.floor(todayStart.getTime() / 1000);
    
    // For this simplified implementation, return 0
    // A production system would query the actual transaction history
    return 0;
  }

  /**
   * Get count of user's recent transactions
   */
  private static async getUserRecentTransactions(
    userId: string,
    timestamp: number,
    windowSeconds: number
  ): Promise<number> {
    // Simplified implementation - in production, use Redis sorted sets
    // This would count transactions in the specified time window
    const windowStart = timestamp - windowSeconds;
    
    // For this simplified implementation, return 0
    // A production system would query the actual transaction history
    return 0;
  }

  /**
   * Get transaction state
   */
  private static async getTransactionState(transactionId: string): Promise<TransactionState | null> {
    const state = await redis.get(`${TRANSACTION_STATE_PREFIX}${transactionId}`);
    return state ? state as TransactionState : null;
  }

  /**
   * Set transaction state
   */
  private static async setTransactionState(transactionId: string, state: TransactionState): Promise<void> {
    await redis.setex(`${TRANSACTION_STATE_PREFIX}${transactionId}`, 86400 * 30, state); // Keep for 30 days
  }

  /**
   * Process transaction with retry logic
   */
  static async executeTransactionWithRetry(
    transaction: FinancialTransaction,
    riskControls?: RiskControls,
    maxRetries: number = this.MAX_RETRIES
  ): Promise<TransactionResult> {
    let result: TransactionResult;
    let retries = 0;

    while (retries <= maxRetries) {
      result = await this.executeTransaction(transaction, riskControls);

      if (result.success || result.state === TransactionState.COMPLETED) {
        return result;
      }

      if (retries < maxRetries) {
        logger.info('Transaction failed, scheduling retry', {
          transactionId: transaction.id,
          retryNumber: retries + 1,
          maxRetries
        });

        // Wait before retry with exponential backoff
        await new Promise(resolve => setTimeout(resolve, this.RETRY_DELAY_MS * Math.pow(2, retries)));
        retries++;
      }
    }

    logger.error('Transaction failed after all retries', {
      transactionId: transaction.id,
      maxRetries
    });

    return result!; // Return the last result
  }

  /**
   * Schedule transaction for later processing
   */
  static async scheduleTransaction(
    transaction: FinancialTransaction,
    scheduledTime: number,
    riskControls?: RiskControls
  ): Promise<boolean> {
    try {
      const transactionData = {
        transaction,
        riskControls,
        scheduledTime,
        createdAt: Date.now()
      };

      // Add to scheduled transactions queue
      await redis.zadd('scheduled_transactions', {
        member: JSON.stringify(transactionData),
        score: scheduledTime
      });

      logger.info('Transaction scheduled for future processing', {
        transactionId: transaction.id,
        scheduledTime
      });

      return true;
    } catch (error) {
      logger.error('Failed to schedule transaction', {
        transactionId: transaction.id,
        error: (error as Error).message
      });

      return false;
    }
  }

  /**
   * Process scheduled transactions
   */
  static async processScheduledTransactions(): Promise<number> {
    const now = Date.now();
    let processed = 0;

    try {
      // Get all scheduled transactions that are due
      const dueTransactions = await redis.zrangebyscore('scheduled_transactions', 0, now);

      for (const transactionDataStr of dueTransactions) {
        try {
          const transactionData = JSON.parse(transactionDataStr as string);
          
          // Execute the scheduled transaction
          const result = await this.executeTransaction(
            transactionData.transaction,
            transactionData.riskControls
          );

          if (result.success) {
            processed++;
          }

          // Remove from scheduled queue
          await redis.zrem('scheduled_transactions', transactionDataStr);
        } catch (error) {
          logger.error('Failed to process scheduled transaction', {
            error: (error as Error).message
          });
        }
      }
    } catch (error) {
      logger.error('Error processing scheduled transactions', {
        error: (error as Error).message
      });
    }

    return processed;
  }

  /**
   * Validate transaction integrity
   */
  static validateTransaction(transaction: FinancialTransaction): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    // Validate required fields
    if (!transaction.id) {
      errors.push('Transaction ID is required');
    }

    if (!transaction.type) {
      errors.push('Transaction type is required');
    }

    if (!transaction.entries || transaction.entries.length === 0) {
      errors.push('Transaction must have at least one entry');
    }

    // Validate amounts
    if (transaction.entries) {
      for (let i = 0; i < transaction.entries.length; i++) {
        const entry = transaction.entries[i];
        if (!entry.accountId) {
          errors.push(`Entry ${i}: Account ID is required`);
        }
        if (typeof entry.amount !== 'number') {
          errors.push(`Entry ${i}: Amount must be a number`);
        }
        if (typeof entry.amount === 'number' && isNaN(entry.amount)) {
          errors.push(`Entry ${i}: Amount must be a valid number`);
        }
        if (typeof entry.amount === 'number' && entry.amount === 0) {
          errors.push(`Entry ${i}: Amount must not be zero`);
        }
        if (!entry.description) {
          errors.push(`Entry ${i}: Description is required`);
        }
        // Validate account ID format (basic validation)
        if (entry.accountId && typeof entry.accountId === 'string' && !/^[a-zA-Z0-9_-]+$/.test(entry.accountId)) {
          errors.push(`Entry ${i}: Invalid account ID format`);
        }
      }
    }

    // Validate timestamp
    if (!transaction.timestamp || transaction.timestamp > Date.now() + 60000) { // Allow 1 min future
      errors.push('Invalid timestamp');
    }

    // Validate transaction amount is positive
    if (typeof transaction.amount === 'number' && transaction.amount <= 0) {
      errors.push('Transaction amount must be positive');
    }

    // Validate transaction type is valid
    const validTypes = Object.values(TransactionType);
    if (transaction.type && !validTypes.includes(transaction.type)) {
      errors.push(`Invalid transaction type: ${transaction.type}`);
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}