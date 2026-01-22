import { createHash } from 'crypto';
import { logger } from '../logger';

export interface LedgerEntry {
  id: string;
  previousHash: string;
  timestamp: number;
  transactionId: string;
  userId: string;
  action: 'deposit' | 'withdrawal' | 'transfer' | 'balance_check' | 'freeze' | 'unfreeze';
  amount?: number;
  currency?: string;
  fromWallet?: string;
  toWallet?: string;
  status: 'pending' | 'confirmed' | 'failed' | 'reversed';
  metadata: Record<string, any>;
  signature: string;
  hash: string;
}

export interface TransactionIntent {
  id: string;
  userId: string;
  fromWallet: string;
  toWallet: string;
  amount: number;
  currency: string;
  type: 'transfer' | 'withdrawal' | 'deposit';
  createdAt: number;
  expiresAt: number;
  status: 'pending' | 'authorized' | 'settled' | 'failed' | 'cancelled';
  authorizedBy?: string;
  settledBy?: string;
}

export class ImmutableLedger {
  private entries: LedgerEntry[] = [];
  private readonly genesisHash = '0'.repeat(64);
  
  constructor() {
    // Initialize with genesis entry
    const genesisEntry: LedgerEntry = {
      id: 'genesis',
      previousHash: this.genesisHash,
      timestamp: Date.now(),
      transactionId: 'genesis',
      userId: 'system',
      action: 'system_init',
      status: 'confirmed',
      metadata: { message: 'Ledger initialized' },
      signature: '',
      hash: ''
    };
    
    // Self-sign the genesis entry
    const serialized = JSON.stringify({
      previousHash: genesisEntry.previousHash,
      timestamp: genesisEntry.timestamp,
      transactionId: genesisEntry.transactionId,
      userId: genesisEntry.userId,
      action: genesisEntry.action,
      status: genesisEntry.status,
      metadata: genesisEntry.metadata
    });
    
    genesisEntry.hash = createHash('sha256').update(serialized).digest('hex');
    this.entries.push(genesisEntry);
    
    logger.info('Financial Core: Immutable ledger initialized', {
      component: 'ledger',
      hash: genesisEntry.hash
    });
  }

  /**
   * Add a new entry to the ledger with cryptographic chaining
   */
  async addEntry(entryData: Omit<LedgerEntry, 'id' | 'previousHash' | 'hash' | 'signature'>): Promise<LedgerEntry> {
    const previousEntry = this.entries[this.entries.length - 1];
    const newId = this.generateId();
    
    const newEntry: LedgerEntry = {
      ...entryData,
      id: newId,
      previousHash: previousEntry.hash,
      hash: '',
      signature: ''
    };

    // Create hash of the entry
    const serialized = JSON.stringify({
      previousHash: newEntry.previousHash,
      timestamp: newEntry.timestamp,
      transactionId: newEntry.transactionId,
      userId: newEntry.userId,
      action: newEntry.action,
      amount: newEntry.amount,
      currency: newEntry.currency,
      fromWallet: newEntry.fromWallet,
      toWallet: newEntry.toWallet,
      status: newEntry.status,
      metadata: newEntry.metadata
    });

    newEntry.hash = createHash('sha256').update(serialized).digest('hex');
    
    // In production, this would be signed by an HSM or secure key manager
    // For now, we simulate the signature field
    newEntry.signature = this.simulateSecureSignature(newEntry.hash);

    this.entries.push(newEntry);
    
    logger.audit('Ledger Entry Added', {
      component: 'ledger',
      entryId: newEntry.id,
      action: newEntry.action,
      userId: newEntry.userId,
      transactionId: newEntry.transactionId,
      hash: newEntry.hash,
      previousHash: newEntry.previousHash
    });

    return newEntry;
  }

  /**
   * Verify the integrity of the entire ledger chain
   */
  verifyIntegrity(): boolean {
    for (let i = 1; i < this.entries.length; i++) {
      const current = this.entries[i];
      const previous = this.entries[i - 1];

      // Check if the previous hash matches
      if (current.previousHash !== previous.hash) {
        logger.error('Ledger integrity violation detected', {
          component: 'ledger',
          position: i,
          currentPreviousHash: current.previousHash,
          expectedPreviousHash: previous.hash
        });
        return false;
      }

      // Recalculate and verify the hash
      const serialized = JSON.stringify({
        previousHash: current.previousHash,
        timestamp: current.timestamp,
        transactionId: current.transactionId,
        userId: current.userId,
        action: current.action,
        amount: current.amount,
        currency: current.currency,
        fromWallet: current.fromWallet,
        toWallet: current.toWallet,
        status: current.status,
        metadata: current.metadata
      });

      const recalculatedHash = createHash('sha256').update(serialized).digest('hex');
      if (recalculatedHash !== current.hash) {
        logger.error('Ledger hash mismatch detected', {
          component: 'ledger',
          position: i,
          calculatedHash: recalculatedHash,
          storedHash: current.hash
        });
        return false;
      }
    }

    logger.info('Ledger integrity verified successfully', {
      component: 'ledger',
      totalEntries: this.entries.length
    });
    return true;
  }

  getEntries(): readonly LedgerEntry[] {
    return [...this.entries]; // Return immutable copy
  }

  getEntryById(id: string): LedgerEntry | undefined {
    return this.entries.find(entry => entry.id === id);
  }

  getEntriesByUserId(userId: string): LedgerEntry[] {
    return this.entries.filter(entry => entry.userId === userId);
  }

  getEntriesByTransactionId(transactionId: string): LedgerEntry[] {
    return this.entries.filter(entry => entry.transactionId === transactionId);
  }

  private generateId(): string {
    return `${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }

  private simulateSecureSignature(hash: string): string {
    // In production, this would be replaced with actual HSM/MPC signing
    // This is just a placeholder to maintain the interface
    return `SIG_${hash.substring(0, 32)}`;
  }
}

// Global singleton instance
let ledgerInstance: ImmutableLedger | null = null;

export function getLedger(): ImmutableLedger {
  if (!ledgerInstance) {
    ledgerInstance = new ImmutableLedger();
  }
  return ledgerInstance;
}