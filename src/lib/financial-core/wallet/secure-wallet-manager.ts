import { createHash, randomBytes } from 'crypto';
import { logger } from '../logger';
import { getLedger } from '../ledger/immutable-ledger';

export interface Wallet {
  id: string;
  userId: string;
  publicKey: string; // Public key for the wallet (stored securely)
  currency: string;
  balance: number;
  status: 'active' | 'frozen' | 'closed';
  createdAt: number;
  updatedAt: number;
}

export interface WalletCreationRequest {
  userId: string;
  currency: string;
}

export interface TransactionRequest {
  fromWalletId: string;
  toWalletId: string;
  amount: number;
  currency: string;
  userId: string;
  description?: string;
}

export interface SignedTransaction {
  transaction: TransactionRequest;
  signature: string;
  timestamp: number;
}

export interface ExternalSignerInterface {
  signTransaction(transaction: TransactionRequest): Promise<string>;
  getPublicKey(): Promise<string>;
  validateSignature(data: string, signature: string, publicKey: string): Promise<boolean>;
}

/**
 * OUT OF SCOPE – UNSAFE WITHOUT HSM / MPC / INFRA
 * This is a placeholder implementation showing the interface
 * that would connect to actual HSM/MPC systems in production.
 */
class MockExternalSigner implements ExternalSignerInterface {
  private keys = new Map<string, { privateKey: string; publicKey: string }>();

  async signTransaction(transaction: TransactionRequest): Promise<string> {
    // In production, this would connect to HSM/MPC
    const serialized = JSON.stringify({
      fromWalletId: transaction.fromWalletId,
      toWalletId: transaction.toWalletId,
      amount: transaction.amount,
      currency: transaction.currency,
      userId: transaction.userId,
      timestamp: Date.now()
    });

    // Mock signature - in production this happens in HSM
    const signature = createHash('sha256')
      .update(serialized)
      .digest('hex');

    logger.warn('Using mock signer - NOT PRODUCTION SAFE', {
      component: 'wallet-security',
      walletId: transaction.fromWalletId
    });

    return signature;
  }

  async getPublicKey(): Promise<string> {
    // Generate a mock key pair
    const keyId = randomBytes(16).toString('hex');
    const privateKey = randomBytes(32).toString('hex');
    const publicKey = createHash('sha256')
      .update(privateKey)
      .digest('hex');

    this.keys.set(keyId, { privateKey, publicKey });

    return publicKey;
  }

  async validateSignature(data: string, signature: string, publicKey: string): Promise<boolean> {
    // In production, this would verify using HSM/MPC
    const expectedSignature = createHash('sha256')
      .update(data)
      .digest('hex');

    return signature === expectedSignature;
  }
}

export class SecureWalletManager {
  private wallets = new Map<string, Wallet>();
  private externalSigner: ExternalSignerInterface;
  private readonly maxTransactionAmount = 1000000; // Max $1M per transaction

  constructor(externalSigner?: ExternalSignerInterface) {
    this.externalSigner = externalSigner || new MockExternalSigner();
    
    logger.info('Secure Wallet Manager initialized', {
      component: 'wallet-security',
      signerType: externalSigner ? 'production' : 'mock'
    });
  }

  /**
   * Create a new wallet for a user
   */
  async createWallet(request: WalletCreationRequest): Promise<Wallet> {
    const walletId = this.generateId();
    const publicKey = await this.externalSigner.getPublicKey();

    const newWallet: Wallet = {
      id: walletId,
      userId: request.userId,
      publicKey,
      currency: request.currency,
      balance: 0,
      status: 'active',
      createdAt: Date.now(),
      updatedAt: Date.now()
    };

    this.wallets.set(walletId, newWallet);

    // Log wallet creation in ledger
    const ledger = getLedger();
    await ledger.addEntry({
      transactionId: `create-wallet-${walletId}`,
      userId: request.userId,
      action: 'deposit', // Initial deposit of 0
      status: 'confirmed',
      metadata: {
        walletId,
        currency: request.currency,
        initialBalance: 0
      }
    });

    logger.audit('Wallet Created', {
      component: 'wallet-security',
      userId: request.userId,
      walletId,
      currency: request.currency
    });

    return newWallet;
  }

  /**
   * Get wallet by ID
   */
  async getWallet(walletId: string): Promise<Wallet | null> {
    const wallet = this.wallets.get(walletId);
    if (!wallet) {
      logger.warn('Attempt to access non-existent wallet', {
        component: 'wallet-security',
        walletId
      });
      return null;
    }

    return { ...wallet }; // Return immutable copy
  }

  /**
   * Get all wallets for a user
   */
  async getUserWallets(userId: string): Promise<Wallet[]> {
    const userWallets: Wallet[] = [];

    for (const wallet of this.wallets.values()) {
      if (wallet.userId === userId) {
        userWallets.push({ ...wallet }); // Return immutable copy
      }
    }

    return userWallets;
  }

  /**
   * Process a secure transaction between wallets
   */
  async processTransaction(transaction: TransactionRequest): Promise<{
    success: boolean;
    transactionId: string;
    error?: string;
  }> {
    const transactionId = this.generateId();
    
    try {
      // Validate transaction request
      const validation = this.validateTransaction(transaction);
      if (!validation.valid) {
        logger.securityEvent('Transaction Validation Failed', {
          component: 'wallet-security',
          transactionId,
          userId: transaction.userId,
          errors: validation.errors
        });
        
        return {
          success: false,
          transactionId,
          error: validation.errors.join(', ')
        };
      }

      // Get wallets
      const fromWallet = this.wallets.get(transaction.fromWalletId);
      const toWallet = this.wallets.get(transaction.toWalletId);

      if (!fromWallet || !toWallet) {
        return {
          success: false,
          transactionId,
          error: 'One or both wallets not found'
        };
      }

      // Check if wallets are active
      if (fromWallet.status !== 'active' || toWallet.status !== 'active') {
        return {
          success: false,
          transactionId,
          error: 'One or both wallets are not active'
        };
      }

      // Check balance
      if (fromWallet.balance < transaction.amount) {
        return {
          success: false,
          transactionId,
          error: 'Insufficient balance'
        };
      }

      // Check transaction limits
      if (transaction.amount > this.maxTransactionAmount) {
        return {
          success: false,
          transactionId,
          error: `Transaction amount exceeds limit of ${this.maxTransactionAmount}`
        };
      }

      // Sign the transaction using external signer (HSM/MPC)
      const signature = await this.externalSigner.signTransaction(transaction);

      // Verify the signature (in production this would happen in HSM)
      const serializedTx = JSON.stringify({
        fromWalletId: transaction.fromWalletId,
        toWalletId: transaction.toWalletId,
        amount: transaction.amount,
        currency: transaction.currency,
        userId: transaction.userId,
        timestamp: Date.now()
      });

      const isValidSignature = await this.externalSigner.validateSignature(
        serializedTx,
        signature,
        fromWallet.publicKey
      );

      if (!isValidSignature) {
        logger.securityEvent('Invalid Transaction Signature', {
          component: 'wallet-security',
          transactionId,
          userId: transaction.userId
        });

        return {
          success: false,
          transactionId,
          error: 'Invalid transaction signature'
        };
      }

      // Perform atomic balance update
      const originalFromBalance = fromWallet.balance;
      const originalToBalance = toWallet.balance;

      // Update balances
      fromWallet.balance -= transaction.amount;
      toWallet.balance += transaction.amount;
      fromWallet.updatedAt = Date.now();
      toWallet.updatedAt = Date.now();

      // Add entries to ledger
      const ledger = getLedger();
      
      // Debit entry
      await ledger.addEntry({
        transactionId,
        userId: transaction.userId,
        action: 'withdrawal',
        amount: transaction.amount,
        currency: transaction.currency,
        fromWallet: transaction.fromWalletId,
        toWallet: transaction.toWalletId,
        status: 'confirmed',
        metadata: {
          description: transaction.description || 'Transfer',
          signature
        }
      });

      // Credit entry
      await ledger.addEntry({
        transactionId,
        userId: toWallet.userId,
        action: 'deposit',
        amount: transaction.amount,
        currency: transaction.currency,
        fromWallet: transaction.fromWalletId,
        toWallet: transaction.toWalletId,
        status: 'confirmed',
        metadata: {
          description: transaction.description || 'Transfer received',
          signature
        }
      });

      logger.audit('Transaction Processed Successfully', {
        component: 'wallet-security',
        transactionId,
        fromWalletId: transaction.fromWalletId,
        toWalletId: transaction.toWalletId,
        amount: transaction.amount,
        currency: transaction.currency,
        userId: transaction.userId
      });

      return {
        success: true,
        transactionId
      };

    } catch (error) {
      logger.error('Transaction Processing Failed', {
        component: 'wallet-security',
        transactionId,
        userId: transaction.userId,
        error: error instanceof Error ? error.message : String(error)
      });

      return {
        success: false,
        transactionId,
        error: 'Transaction processing failed'
      };
    }
  }

  /**
   * Freeze a wallet (kill switch functionality)
   */
  async freezeWallet(walletId: string, reason: string = 'admin_action'): Promise<boolean> {
    const wallet = this.wallets.get(walletId);
    if (!wallet) {
      return false;
    }

    const originalStatus = wallet.status;
    wallet.status = 'frozen';
    wallet.updatedAt = Date.now();

    // Log in ledger
    const ledger = getLedger();
    await ledger.addEntry({
      transactionId: `freeze-${walletId}`,
      userId: wallet.userId,
      action: 'freeze',
      status: 'confirmed',
      metadata: {
        walletId,
        originalStatus,
        reason
      }
    });

    logger.audit('Wallet Frozen', {
      component: 'wallet-security',
      walletId,
      userId: wallet.userId,
      reason
    });

    return true;
  }

  /**
   * Unfreeze a wallet
   */
  async unfreezeWallet(walletId: string, reason: string = 'admin_action'): Promise<boolean> {
    const wallet = this.wallets.get(walletId);
    if (!wallet || wallet.status !== 'frozen') {
      return false;
    }

    const originalStatus = wallet.status;
    wallet.status = 'active';
    wallet.updatedAt = Date.now();

    // Log in ledger
    const ledger = getLedger();
    await ledger.addEntry({
      transactionId: `unfreeze-${walletId}`,
      userId: wallet.userId,
      action: 'unfreeze',
      status: 'confirmed',
      metadata: {
        walletId,
        originalStatus,
        reason
      }
    });

    logger.audit('Wallet Unfrozen', {
      component: 'wallet-security',
      walletId,
      userId: wallet.userId,
      reason
    });

    return true;
  }

  /**
   * Get wallet balance
   */
  async getBalance(walletId: string): Promise<number | null> {
    const wallet = this.wallets.get(walletId);
    return wallet ? wallet.balance : null;
  }

  private generateId(): string {
    return `${Date.now()}-${randomBytes(8).toString('hex')}`;
  }

  private validateTransaction(transaction: TransactionRequest): {
    valid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    if (transaction.amount <= 0) {
      errors.push('Amount must be positive');
    }

    if (transaction.fromWalletId === transaction.toWalletId) {
      errors.push('From and to wallets cannot be the same');
    }

    if (!transaction.fromWalletId || !transaction.toWalletId) {
      errors.push('Both from and to wallet IDs are required');
    }

    if (!transaction.currency) {
      errors.push('Currency is required');
    }

    if (transaction.amount > Number.MAX_SAFE_INTEGER) {
      errors.push('Amount too large');
    }

    return {
      valid: errors.length === 0,
      errors
    };
  }
}

// Global instance
let walletManager: SecureWalletManager | null = null;

export function getWalletManager(externalSigner?: ExternalSignerInterface): SecureWalletManager {
  if (!walletManager) {
    walletManager = new SecureWalletManager(externalSigner);
  }
  return walletManager;
}