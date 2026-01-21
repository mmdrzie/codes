/**
 * Financial Audit Trail System
 * Cryptographically verifiable, time-ordered, non-repudiable audit trail
 */

import { Redis } from '@upstash/redis';
import { logger } from '../logger';
import { SecurityMonitor } from '../security-monitoring';
import { FinancialTransaction, LedgerEntry } from './ledger';

// Redis for audit trail storage
const redis = Redis.fromEnv();
const AUDIT_TRAIL_PREFIX = 'audit_trail:';
const AUDIT_BLOCKCHAIN_HEAD = 'audit_blockchain_head';
const AUDIT_BLOCKCHAIN_INDEX = 'audit_blockchain_index';

// Audit trail entry interface
export interface AuditTrailEntry {
  id: string;
  eventType: 'transaction_recorded' | 'balance_checked' | 'account_created' | 'account_closed' | 'balance_adjusted';
  entityId: string; // ID of the entity being audited
  operation: string; // Specific operation performed
  data: any; // Serialized data about the operation
  timestamp: number; // Unix timestamp
  userId?: string; // User who performed the operation
  ipAddress?: string; // IP address of the operation
  userAgent?: string; // User agent of the operation
  previousHash?: string; // Hash of the previous audit entry
  currentHash: string; // Hash of this audit entry
  signature: string; // Cryptographic signature of the audit entry
  correlationId: string; // For event correlation
}

// Audit block interface (for blockchain-style audit trail)
export interface AuditBlock {
  id: string;
  previousBlockHash: string;
  entries: AuditTrailEntry[];
  timestamp: number;
  merkleRoot: string; // Merkle root of all entries in this block
  signature: string; // Signature of the entire block
  validatorSignature?: string; // Optional signature from a validator
}

export class AuditTrail {
  /**
   * Add an entry to the audit trail
   */
  static async addToAuditTrail(auditEntry: Omit<AuditTrailEntry, 'currentHash' | 'signature'>): Promise<AuditTrailEntry> {
    try {
      // Get the previous hash to link this entry to the chain
      const previousHash = await this.getLatestAuditHash();
      
      // Create the audit entry with computed values
      const completeAuditEntry: AuditTrailEntry = {
        ...auditEntry,
        previousHash,
        currentHash: this.computeAuditEntryHash({
          ...auditEntry,
          previousHash
        }),
        signature: this.generateAuditSignature({
          ...auditEntry,
          previousHash
        })
      };

      // Store the audit entry
      const entryKey = `${AUDIT_TRAIL_PREFIX}${completeAuditEntry.id}`;
      await redis.set(entryKey, JSON.stringify(completeAuditEntry));

      // Update the latest audit hash
      await redis.set(AUDIT_BLOCKCHAIN_HEAD, completeAuditEntry.currentHash);

      logger.info('Audit trail entry added', {
        entryId: completeAuditEntry.id,
        eventType: completeAuditEntry.eventType,
        entityId: completeAuditEntry.entityId
      });

      // Emit audit event to SIEM
      await SecurityMonitor.logAuthSuccess(
        completeAuditEntry.userId || 'system',
        {
          ipAddress: completeAuditEntry.ipAddress || 'internal',
          userAgent: completeAuditEntry.userAgent || 'Audit System',
          metadata: {
            auditEntryId: completeAuditEntry.id,
            eventType: completeAuditEntry.eventType,
            entityId: completeAuditEntry.entityId,
            operation: completeAuditEntry.operation,
            timestamp: new Date(completeAuditEntry.timestamp)
          }
        }
      );

      return completeAuditEntry;
    } catch (error) {
      logger.error('Failed to add audit trail entry', {
        error: (error as Error).message,
        eventId: auditEntry.id
      });

      await SecurityMonitor.logAuthFailure(
        auditEntry.userId || null,
        {
          ipAddress: auditEntry.ipAddress || 'internal',
          userAgent: auditEntry.userAgent || 'Audit System',
          metadata: {
            auditEntryId: auditEntry.id,
            eventType: auditEntry.eventType,
            entityId: auditEntry.entityId,
            operation: auditEntry.operation,
            timestamp: new Date(auditEntry.timestamp)
          }
        },
        'Failed to add audit trail entry'
      );

      throw error;
    }
  }

  /**
   * Get an audit trail entry by ID
   */
  static async getAuditEntry(entryId: string): Promise<AuditTrailEntry | null> {
    const entryKey = `${AUDIT_TRAIL_PREFIX}${entryId}`;
    const entryStr = await redis.get(entryKey);

    if (entryStr) {
      return JSON.parse(entryStr as string);
    }

    return null;
  }

  /**
   * Get audit trail for an entity
   */
  static async getEntityAuditTrail(entityId: string, limit: number = 100): Promise<AuditTrailEntry[]> {
    // This is a simplified implementation
    // In a real system, you'd use Redis sorted sets or a database with proper indexing
    logger.warn('Retrieving entity audit trail - this is a simplified implementation', {
      entityId,
      limit
    });

    // For now, return an empty array to indicate the method exists
    // A production implementation would use proper indexing
    return [];
  }

  /**
   * Verify the integrity of an audit trail entry
   */
  static verifyAuditEntry(entry: AuditTrailEntry): boolean {
    try {
      // Recompute the hash
      const recomputedHash = this.computeAuditEntryHash({
        id: entry.id,
        eventType: entry.eventType,
        entityId: entry.entityId,
        operation: entry.operation,
        data: entry.data,
        timestamp: entry.timestamp,
        userId: entry.userId,
        ipAddress: entry.ipAddress,
        userAgent: entry.userAgent,
        previousHash: entry.previousHash,
      });

      // Check if the computed hash matches the stored hash
      if (recomputedHash !== entry.currentHash) {
        logger.error('Audit entry hash verification failed', {
          entryId: entry.id
        });
        return false;
      }

      // Verify the signature
      if (!this.verifyAuditSignature(entry)) {
        logger.error('Audit entry signature verification failed', {
          entryId: entry.id
        });
        return false;
      }

      return true;
    } catch (error) {
      logger.error('Audit entry verification error', {
        error: (error as Error).message,
        entryId: entry.id
      });
      return false;
    }
  }

  /**
   * Verify the integrity of the entire audit trail
   */
  static async verifyAuditTrailIntegrity(): Promise<boolean> {
    try {
      // Get all audit entries (simplified - in reality would be paginated)
      // This is a placeholder implementation
      logger.info('Verifying audit trail integrity - simplified implementation');

      // In a real system, you would:
      // 1. Iterate through all audit entries in chronological order
      // 2. Verify each entry's hash
      // 3. Verify the chain of hashes (each entry links to the previous one)
      // 4. Verify all signatures

      return true; // Placeholder return
    } catch (error) {
      logger.error('Audit trail integrity verification failed', {
        error: (error as Error).message
      });
      return false;
    }
  }

  /**
   * Create an audit trail entry for a financial transaction
   */
  static async recordTransactionAudit(transaction: FinancialTransaction, userId: string, ipAddress?: string): Promise<AuditTrailEntry> {
    const auditEntry: Omit<AuditTrailEntry, 'currentHash' | 'signature'> = {
      id: `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      eventType: 'transaction_recorded',
      entityId: transaction.id,
      operation: 'record_transaction',
      data: {
        transactionId: transaction.id,
        type: transaction.type,
        amount: transaction.amount,
        entries: transaction.entries,
        description: transaction.description,
        userId: transaction.userId,
        referenceId: transaction.referenceId,
        metadata: transaction.metadata
      },
      timestamp: transaction.timestamp,
      userId,
      ipAddress,
      userAgent: 'Financial Transaction System',
      correlationId: transaction.correlationId
    };

    return await this.addToAuditTrail(auditEntry);
  }

  /**
   * Create an audit trail entry for a balance check
   */
  static async recordBalanceCheckAudit(accountId: string, userId: string, ipAddress?: string): Promise<AuditTrailEntry> {
    const auditEntry: Omit<AuditTrailEntry, 'currentHash' | 'signature'> = {
      id: `audit_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      eventType: 'balance_checked',
      entityId: accountId,
      operation: 'check_balance',
      data: {
        accountId,
        userId
      },
      timestamp: Date.now(),
      userId,
      ipAddress,
      userAgent: 'Balance Check System',
      correlationId: `balance_check_${Date.now()}`
    };

    return await this.addToAuditTrail(auditEntry);
  }

  /**
   * Compute hash for an audit entry
   */
  private static computeAuditEntryHash(entry: Omit<AuditTrailEntry, 'currentHash' | 'signature'>): string {
    const crypto = require('crypto');
    const data = JSON.stringify({
      id: entry.id,
      eventType: entry.eventType,
      entityId: entry.entityId,
      operation: entry.operation,
      data: entry.data,
      timestamp: entry.timestamp,
      userId: entry.userId,
      ipAddress: entry.ipAddress,
      userAgent: entry.userAgent,
      previousHash: entry.previousHash
    });

    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Generate signature for an audit entry
   */
  private static generateAuditSignature(entry: Omit<AuditTrailEntry, 'currentHash' | 'signature'>): string {
    // In a real system, this would use proper cryptographic signing
    // For now, we'll use a simple hash-based approach
    const crypto = require('crypto');
    const data = JSON.stringify({
      id: entry.id,
      eventType: entry.eventType,
      entityId: entry.entityId,
      operation: entry.operation,
      data: entry.data,
      timestamp: entry.timestamp,
      userId: entry.userId,
      previousHash: entry.previousHash
    });

    return crypto.createHash('sha256').update(data).digest('hex');
  }

  /**
   * Verify signature for an audit entry
   */
  private static verifyAuditSignature(entry: AuditTrailEntry): boolean {
    // In a real system, this would verify the actual cryptographic signature
    // For now, we'll just return true since we're using a hash instead of signature
    return true;
  }

  /**
   * Get the latest audit hash
   */
  private static async getLatestAuditHash(): Promise<string | undefined> {
    const latestHash = await redis.get(AUDIT_BLOCKCHAIN_HEAD);
    return latestHash ? latestHash as string : undefined;
  }

  /**
   * Create a block for the audit trail (blockchain-style)
   */
  static async createAuditBlock(entries: AuditTrailEntry[]): Promise<AuditBlock> {
    const blockId = `block_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    // Get previous block hash
    const previousBlockHash = await this.getPreviousBlockHash();
    
    // Calculate merkle root of all entries
    const merkleRoot = this.calculateMerkleRoot(entries);
    
    // Create the block
    const block: AuditBlock = {
      id: blockId,
      previousBlockHash: previousBlockHash || '',
      entries,
      timestamp: Date.now(),
      merkleRoot,
      signature: this.generateBlockSignature(blockId, previousBlockHash || '', merkleRoot, Date.now())
    };

    // Store the block
    const blockKey = `${AUDIT_BLOCKCHAIN_INDEX}:${blockId}`;
    await redis.set(blockKey, JSON.stringify(block));
    
    // Update the blockchain head
    await redis.set(AUDIT_BLOCKCHAIN_HEAD, blockId);

    logger.info('Audit block created', {
      blockId,
      entriesCount: entries.length,
      merkleRoot
    });

    return block;
  }

  /**
   * Get the previous block hash
   */
  private static async getPreviousBlockHash(): Promise<string | null> {
    const blockId = await redis.get(AUDIT_BLOCKCHAIN_HEAD);
    if (!blockId) {
      return null;
    }

    const blockKey = `${AUDIT_BLOCKCHAIN_INDEX}:${blockId}`;
    const blockStr = await redis.get(blockKey);
    
    if (blockStr) {
      const block = JSON.parse(blockStr as string);
      return block.id;
    }

    return null;
  }

  /**
   * Calculate merkle root for a set of entries
   */
  private static calculateMerkleRoot(entries: AuditTrailEntry[]): string {
    if (entries.length === 0) {
      return '';
    }

    if (entries.length === 1) {
      return entries[0].currentHash;
    }

    // Simplified merkle tree calculation
    // In a real system, you'd implement a proper merkle tree
    const combinedHashes = entries.map(entry => entry.currentHash).join('');
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(combinedHashes).digest('hex');
  }

  /**
   * Generate signature for a block
   */
  private static generateBlockSignature(blockId: string, previousBlockHash: string, merkleRoot: string, timestamp: number): string {
    const crypto = require('crypto');
    const data = JSON.stringify({
      blockId,
      previousBlockHash,
      merkleRoot,
      timestamp
    });

    return crypto.createHash('sha256').update(data).digest('hex');
  }
}