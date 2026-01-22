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

export interface LedgerSnapshot {
  id: string;
  timestamp: number;
  entryCount: number;
  merkleRoot: string;
  hash: string;
}

export class ImmutableLedger {
  private entries: LedgerEntry[] = [];
  private readonly genesisHash = '0'.repeat(64);
  private snapshots: LedgerSnapshot[] = [];
  private snapshotInterval: number; // Number of entries between snapshots
  
  constructor(snapshotInterval: number = 100) { // Default to snapshot every 100 entries
    this.snapshotInterval = snapshotInterval;
    
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
    
    // Create initial snapshot for genesis
    this.createSnapshot();
    
    logger.info('Financial Core: Immutable ledger initialized', {
      component: 'ledger',
      hash: genesisEntry.hash,
      snapshotInterval: this.snapshotInterval
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

    // Create a snapshot if we've reached the interval threshold
    if (this.entries.length % this.snapshotInterval === 0) {
      this.createSnapshot();
    }

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

  /**
   * Calculate the Merkle root for the current ledger entries
   */
  private calculateMerkleRoot(entries: LedgerEntry[]): string {
    if (entries.length === 0) {
      return createHash('sha256').update('').digest('hex');
    }
    
    if (entries.length === 1) {
      return entries[0].hash;
    }

    // Create leaf hashes for all entries
    let hashes = entries.map(entry => entry.hash);

    // Build the Merkle tree bottom-up
    while (hashes.length > 1) {
      const newLevel = [];
      
      for (let i = 0; i < hashes.length; i += 2) {
        const left = hashes[i];
        const right = i + 1 < hashes.length ? hashes[i + 1] : hashes[i]; // Duplicate if odd
        
        const combined = createHash('sha256')
          .update(left + right)
          .digest('hex');
        
        newLevel.push(combined);
      }
      
      hashes = newLevel;
    }
    
    return hashes[0];
  }

  /**
   * Create a snapshot of the current ledger state
   */
  private createSnapshot(): void {
    if (this.entries.length === 0) {
      return;
    }

    const merkleRoot = this.calculateMerkleRoot(this.entries);
    const snapshotId = `snapshot-${Date.now()}`;
    
    // Create a hash of the snapshot data for integrity verification
    const snapshotData = {
      id: snapshotId,
      timestamp: Date.now(),
      entryCount: this.entries.length,
      merkleRoot
    };
    
    const snapshotHash = createHash('sha256')
      .update(JSON.stringify(snapshotData))
      .digest('hex');

    const snapshot: LedgerSnapshot = {
      ...snapshotData,
      hash: snapshotHash
    };

    this.snapshots.push(snapshot);
    
    logger.info('Ledger snapshot created', {
      component: 'ledger',
      snapshotId,
      entryCount: this.entries.length,
      merkleRoot
    });
  }

  /**
   * Verify a snapshot integrity
   */
  private verifySnapshot(snapshot: LedgerSnapshot): boolean {
    const snapshotData = {
      id: snapshot.id,
      timestamp: snapshot.timestamp,
      entryCount: snapshot.entryCount,
      merkleRoot: snapshot.merkleRoot
    };
    
    const recalculatedHash = createHash('sha256')
      .update(JSON.stringify(snapshotData))
      .digest('hex');
    
    return recalculatedHash === snapshot.hash;
  }

  /**
   * Get all snapshots
   */
  getSnapshots(): readonly LedgerSnapshot[] {
    return [...this.snapshots]; // Return immutable copy
  }

  /**
   * Get latest snapshot
   */
  getLatestSnapshot(): LedgerSnapshot | undefined {
    if (this.snapshots.length === 0) {
      return undefined;
    }
    return this.snapshots[this.snapshots.length - 1];
  }

  /**
   * Verify the integrity of the ledger using snapshots
   */
  async verifyIntegrityWithSnapshots(): Promise<boolean> {
    // First verify basic integrity
    const basicIntegrity = this.verifyIntegrity();
    if (!basicIntegrity) {
      return false;
    }

    // Verify all snapshots
    for (const snapshot of this.snapshots) {
      if (!this.verifySnapshot(snapshot)) {
        logger.error('Ledger snapshot integrity violation detected', {
          component: 'ledger',
          snapshotId: snapshot.id
        });
        return false;
      }
    }

    // Verify that the calculated Merkle root matches the snapshot
    const latestSnapshot = this.getLatestSnapshot();
    if (latestSnapshot && latestSnapshot.entryCount === this.entries.length) {
      const currentMerkleRoot = this.calculateMerkleRoot(this.entries);
      if (currentMerkleRoot !== latestSnapshot.merkleRoot) {
        logger.error('Ledger Merkle root mismatch with latest snapshot', {
          component: 'ledger',
          expected: latestSnapshot.merkleRoot,
          actual: currentMerkleRoot
        });
        return false;
      }
    }

    logger.info('Ledger integrity verified with snapshots', {
      component: 'ledger',
      totalEntries: this.entries.length,
      totalSnapshots: this.snapshots.length
    });

    return true;
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

export function getLedger(snapshotInterval?: number): ImmutableLedger {
  if (!ledgerInstance) {
    ledgerInstance = new ImmutableLedger(snapshotInterval);
  }
  return ledgerInstance;
}